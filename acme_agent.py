import datetime
import dotenv
import json
import os
import pathlib
import requests

from loguru import logger
from urllib.parse import urljoin, urlparse

from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


class AcmeAgent:

    def __init__(self, env_file=None):
        self.base_dir = os.path.abspath(os.path.dirname(__file__))

        if env_file is None:
            env_file = os.path.join(self.base_dir, ".env")

        dotenv.load_dotenv(env_file)

        self.directory = None
        self.nonce = None
        self.authorizations = []
        self.order = None

        self.endpoint_directory = os.environ.get("ACME_API_ENDPOINT_DIRECTORY")
        self.contact_email = os.environ.get("ACME_CONTACT_EMAIL")

        self.public_key_file_path = pathlib.Path(
            os.path.join(self.base_dir, "account", "id_rsa_jwk_public.json")
        )

        self.private_key_file_path = pathlib.Path(
            os.path.join(self.base_dir, "account", "id_rsa_jwk_private.json")
        )

        logger.info(f"ENDPOINT: {self.endpoint_directory}")

        if self.endpoint_directory is None:
            logger.error("could not get env variable: ACME_API_ENDPOINT_DIRECTORY")
            exit()

        self.parse_directory()

        if self.directory is None:
            logger.error("could not retrieve directory of the acme api")
            exit()

        if not self.private_key_file_path.exists():
            # create new account
            key = jwk.JWK.generate(kty="RSA", size=4096)

            self.public_key = key.export_public()
            self.private_key = key.export_private()

            self.private_key_file_path.write_text(self.private_key)
            self.public_key_file_path.write_text(self.public_key)
        else:

            self.private_key = jwk.JWK.from_json(self.private_key_file_path.read_text())

            self.public_key = jwk.JWK.from_json(self.public_key_file_path.read_text())

        self.new_account()

    def parse_directory(self):
        response = self.get_request(self.endpoint_directory)

        if response.status_code == 200:
            self.directory = json.loads(response.text)
        else:
            self.directory = None

    def get_request(self, url):
        parsed = urlparse(url)

        logger.info(f"GET {parsed.path}")

        response = requests.get(url)

        return response

    def head_request(self, url):
        parsed = urlparse(url)

        logger.info(f"HEAD {parsed.path}")

        response = requests.head(url)

        return response

    def post_request(self, url, payload, protected):

        parsed = urlparse(url)

        logger.info(f"POST {parsed.path}")

        #logger.info(json.dumps(payload, indent=4))
        #logger.info(json.dumps(protected, indent=4))

        jws_token = jws.JWS(json_encode(payload))

        jws_token.add_signature(
            key=self.private_key,
            alg=None,
            protected=json_encode(protected),
            header=None,
        )
        signed_payload = jws_token.serialize()

        response = requests.post(
            url, data=signed_payload, headers={"Content-Type": "application/jose+json"}
        )

        logger.info(f"HTTP CODE: {response.status_code}")
        #logger.info(response.text)
        #logger.info(response.headers)

        return response

    def get_nonce(self):
        response = self.head_request(self.directory["newNonce"])

        if response.status_code == 200:
            return response.headers.get("Replay-Nonce", None)
        else:
            return None

    def new_account(self):
        url = self.directory["newAccount"]

        payload = {
            "termsOfServiceAgreed": True,
            "contact": [
                f"mailto:{self.contact_email}",
            ],
        }

        protected = {
            "alg": "RS256",
            "jwk": self.public_key,
            "nonce": self.get_nonce(),
            "url": url,
        }

        response = self.post_request(url, payload, protected)

        if response.status_code in [200, 201]:
            # 200 = account already existed
            # 201 account was created
            self.kid = response.headers.get("location", None)
        else:
            logger.error("could not create account")
            exit()

    def new_order(self, domains: list):
        url = self.directory["newOrder"]

        payload = {"identifiers": []}

        for domain in domains:
            payload["identifiers"].append({"type": "dns", "value": domain})

        protected = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self.get_nonce(),
            "url": url,
        }

        response = self.post_request(url, payload, protected)

        return response

    def get_thumbprint(self):

        return self.public_key.thumbprint()

    def respond_to_challenge(self, url):
        payload = {}
        protected = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self.get_nonce(),
            "url": url,
        }

        response = self.post_request(url, payload, protected)

        return response

    def finalize_order(self, url, csr_string):
        payload = {"csr": csr_string}
        protected = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self.get_nonce(),
            "url": url,
        }

        response = self.post_request(url, payload, protected)

        return response
