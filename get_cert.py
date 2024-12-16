import base64
import glob
import hashlib
import json
import os
import time
import tldextract

from acme_agent import AcmeAgent
from dns_agent import DnsAgent
from datetime import date
from loguru import logger
from pathlib import Path

"""
	+-------------------+--------------------------------+--------------+
	| Action            | Request                        | Response     |
	+-------------------+--------------------------------+--------------+
	| Get directory     | GET  directory                 | 200          |
	|                   |                                |              |
	| Get nonce         | HEAD newNonce                  | 200          |
	|                   |                                |              |
	| Create account    | POST newAccount                | 201 ->       |
	|                   |                                | account      |
	|                   |                                |              |
	| Submit order      | POST newOrder                  | 201 -> order |
	|                   |                                |              |
	| Fetch challenges  | POST-as-GET order's            | 200          |
	|                   | authorization urls             |              |
	|                   |                                |              |
	| Respond to        | POST authorization challenge   | 200          |
	| challenges        | urls                           |              |
	|                   |                                |              |
	| Poll for status   | POST-as-GET order              | 200          |
	|                   |                                |              |
	| Finalize order    | POST order's finalize url      | 200          |
	|                   |                                |              |
	| Poll for status   | POST-as-GET order              | 200          |
	|                   |                                |              |
	| Download          | POST-as-GET order's            | 200          |
	| certificate       | certificate url                |              |
	+-------------------+--------------------------------+--------------+

"""


# 4096 bit modulus like a boss
# https://docs.cossacklabs.com/themis/spec/asymmetric-keypairs/rsa/


def generate_csr(root_domain, san_list, key_size=4096):
    """
    certbot uses these file names:

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem; # managed by Certbot
    """

    csr_file_path = f"./orders/{root_domain}.csr"
    private_key_file_path = f"./orders/{root_domain}.privkey.pem"

    if os.path.isfile(csr_file_path):

        with open(csr_file_path, "r") as f:
            csr_string = f.read()

        return csr_string

    from cryptography import x509

    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    private_key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    san_list = []

    for domain in domain_list:
        san_list.append(x509.DNSName(domain))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    # x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                    # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                    # x509.NameAttribute(NameOID.LOCALITY_NAME, city),
                    # x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
                    # x509.NameAttribute(NameOID.COMMON_NAME, site),
                ]
            )
        )
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )

    csr_bytes = csr.public_bytes(serialization.Encoding.DER)

    csr_bytes_b64 = base64.urlsafe_b64encode(csr_bytes)

    # pythons base64 lib adds new line at the end
    csr_string = csr_bytes_b64.decode().rstrip("=")

    with open(private_key_file_path, "wb") as f:
        f.write(private_key_bytes)

    with open(csr_file_path, "w") as f:
        f.write(csr_string)

    return csr_string


def get_root_domain(domain_list):
    try:
        extract_result = tldextract.extract(domain_list[0].lower())
    except Exception as e:
        logger.error(str(e))
        return None

    return f"{extract_result.domain}.{extract_result.suffix}"


def reduce_domain_to_root(domain) -> str | None:
    try:
        extract_result = tldextract.extract(domain.lower())
    except Exception as e:
        logger.error(str(e))
        return None

    return f"{extract_result.domain}.{extract_result.suffix}"


def filter_domain_list(domain_list, root_domain):
    new_domain_list = []
    for domain in domain_list:
        try:
            extract_result = tldextract.extract(domain.lower())
        except Exception as e:
            logger.error(str(e))
            continue

        current_root_domain = f"{extract_result.domain}.{extract_result.suffix}"

        if not root_domain == current_root_domain:
            logger.info(
                f"skipping {domain}. only certificates for {root_domain} allowed in one order"
            )
            continue

        new_domain_list.append(domain.lower())

    return new_domain_list


def order_cert(raw_domain_list):
    root_domain = get_root_domain(raw_domain_list)

    domain_list = filter_domain_list(raw_domain_list, root_domain)

    cert_file_path = f"./orders/{root_domain}.fullchain.pem"

    if os.path.isfile(cert_file_path):
        logger.info(f"certificate already exists: {cert_file_path}")
        logger.info(f"delete it first if you want to order a new one")
        exit()

    dns_agent = DnsAgent()

    if not root_domain in dns_agent.domains:
        logger.error(f"{root_domain} is not in your possession")

    acme_agent = AcmeAgent()

    response = acme_agent.new_order(domain_list)

    if not response.status_code == 201:
        logger.error("something went wrong while creating the order")
        exit()

    # if 201: order was created or existed already
    # letsencrypt does reuse orders automatically :)

    order = json.loads(response.text)
    order_url = response.headers.get("location", None)

    logger.info(f"ORDER URL: {order_url}")

    while not order["status"] == "ready":

        for authz_url in order["authorizations"]:
            response = acme_agent.get_request(authz_url)

            authorization = json.loads(response.text)

            current_domain = authorization["identifier"]["value"]

            token = None
            status = None
            challenge_url = None

            for challenge in authorization["challenges"]:
                if not challenge["type"] == "dns-01":
                    continue

                status = challenge["status"]
                token = challenge["token"]
                challenge_url = challenge["url"]

                break

            if status == "pending":

                # https://datatracker.ietf.org/doc/html/rfc8555#section-8.1
                key_authorization = f"{token}.{acme_agent.get_thumbprint()}"
                key_authorization = hashlib.sha256(
                    key_authorization.encode("utf-8")
                ).digest()

                # base64 library adds new line at the end
                txt_record = (
                    base64.urlsafe_b64encode(key_authorization).decode().rstrip("=")
                )

                if not len(txt_record) == 43:
                    logger.error("wrong dns-01 challenge value length")
                    exit()

                host = f"_acme-challenge"
                if not current_domain == root_domain:

                    extract_result = tldextract.extract(current_domain)

                    host = f"{host}.{extract_result.subdomain}"

                logger.info(f"HOST FOR TXT RECORD: {host}")
                dns_agent.create_record(root_domain, host, "TXT", txt_record)

                external_records = dns_agent.get_external_records(
                    f"_acme-challenge.{current_domain}", "TXT"
                )

                while not txt_record in external_records:
                    # TODO: implement maximum wait
                    logger.info("waiting 30 seconds to re-check public dns entries")
                    time.sleep(30)
                    external_records = dns_agent.get_external_records(
                        f"_acme-challenge.{current_domain}", "TXT"
                    )

                acme_agent.respond_to_challenge(challenge_url)

        order_response = acme_agent.get_request(order_url)

        order = json.loads(order_response.text)

        logger.info(json.dumps(order, indent=4))

    # we can retrieve the cert
    # create csr , send to finalize url
    csr_string = generate_csr(root_domain, domain_list)

    logger.info(csr_string)

    response = acme_agent.finalize_order(order["finalize"], csr_string)

    if not response.status_code == 200:
        logger.error("something went wrong while finalizing the order")
        exit()

    certificate_url = json.loads(response.text)["certificate"]

    response = acme_agent.get_request(certificate_url)

    if not response.status_code == 200:
        logger.error("could not download cert")
        exit()

    with open(cert_file_path, "wb") as f:
        f.write(response.content)

    logger.info(f"successfully retrieved certificate for {root_domain}")


if __name__ == "__main__":
    # .domains.json overrides everything and has no safety railings ;)
    if Path(Path(__file__).parent / ".domains.json").exists():

        # we just collect the unique root domains and order a wildcard cert for each
        raw_domain_list = json.loads(
            Path(Path(__file__).parent / ".domains.json").read_text()
        )

        root_domain_list = []
        for domain in raw_domain_list:

            root_domain = reduce_domain_to_root(domain)

            if not root_domain in root_domain_list:
                root_domain_list.append(root_domain)

        order_path = Path(Path(__file__).parent / "orders")
        for root_domain in root_domain_list:

            # move old orders into archive folder
            for f in order_path.glob(f"{root_domain}.*"):
                dest_folder = f.parent / "archive"
                dest_file_name = today = date.today().isoformat() + "_" + f.name

                if not dest_folder.exists():
                    dest_folder.mkdir(exist_ok=True)

                f.rename(dest_folder / dest_file_name)

            domain_list = [root_domain, "*." + root_domain]

            order_cert(domain_list)

    else:
        # for now , only sub domains from the first domain are allowed
        # they will be added as SANs to the CSR

        import argparse

        parser = argparse.ArgumentParser(
            description="Order and renew certificates via the Let's Encrypt ACME API and name.com API"
        )
        parser.add_argument(
            "-d",
            "--domain",
            type=str,
            action="append",
            help="Domain Name",
            required=True,
        )

        args = parser.parse_args()

        domain_list = args.domain

        order_cert(domain_list)
