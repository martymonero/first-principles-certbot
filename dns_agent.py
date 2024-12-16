import datetime
import dns.resolver
import dotenv
import json
import os
import requests
import time

from loguru import logger
from urllib.parse import urljoin, urlparse


class DnsAgent:

    def __init__(self, env_file=None):
        self.base_dir = os.path.abspath(os.path.dirname(__file__))

        if env_file is None:
            env_file = os.path.join(self.base_dir, ".env")

        dotenv.load_dotenv(env_file)

        self.domains = []
        self.endpoint = os.environ.get("NAMEDOTCOM_API_ENDPOINT", None)
        self.username = os.environ.get("NAMEDOTCOM_API_USERNAME", None)
        self.token = os.environ.get("NAMEDOTCOM_API_TOKEN", None)

        if self.endpoint is None:
            logger.error(
                "name.com api endpoint is missing. did you prepare the .env file?"
            )
            exit()

        self.get_my_domains()

    def get_my_domains(self):
        url = f"{self.endpoint}/domains"

        response = self.get_request(url)

        if not response.status_code == 200:
            logger.error("could not retrieve domains. check your credentials")
            exit()

        for domain_obj in json.loads(response.text)["domains"]:
            self.domains.append(domain_obj["domainName"])

    def create_record(self, domain, host, record_type, answer, ttl=300):
        url = f"{self.endpoint}/domains/{domain}/records"

        # check if record already exists
        response = self.get_request(url)

        logger.info(response.status_code)
        # logger.info(response.text)

        is_record_existing = False
        if "records" in json.loads(response.text):
            for record in json.loads(response.text)["records"]:
                if not "host" in record:
                    continue

                if record["host"] == host and record["type"] == record_type:

                    if record["answer"] == answer:
                        is_record_existing = True
                    else:
                        record_id = record["id"]
                        logger.info(
                            f"dns record with same host: {host} and type: {record_type} already exists"
                        )
                        logger.info(f"deleting old record with id: {record_id}")

                        self.delete_request(f"{url}/{record_id}")


                        logger.info(f"sleeping to avoid race conditions")
                        time.sleep(5 * 60)

        if is_record_existing:

            logger.info("DNS record already exists")

            return

        payload = {
            "host": host,
            "type": record_type,
            "answer": answer,
            "ttl": ttl,
        }

        response = self.post_request(url, payload)

        logger.info(response.status_code)
        # logger.info(response.text)

    def get_request(self, url):
        parsed = urlparse(url)

        logger.info(f"GET {parsed.path}")

        response = requests.get(url, auth=(self.username, self.token))

        return response

    def post_request(self, url, payload):
        parsed = urlparse(url)

        logger.info(f"POST {parsed.path}")

        response = requests.post(url, json=payload, auth=(self.username, self.token))

        logger.info(response.status_code)
        # logger.info(response.text)

        return response

    def delete_request(self, url):
        parsed = urlparse(url)

        logger.info(f"DELETE {parsed.path}")

        response = requests.delete(url, auth=(self.username, self.token))

        logger.info(response.status_code)

        return response

    def get_external_records(self, domain, record_type):
        resolver = dns.resolver.Resolver()

        # 8.8.8.8 is Google's public DNS server
        resolver.nameservers = ["8.8.8.8"]

        try:
            result = resolver.resolve(domain, record_type)
        except Exception as e:
            logger.error(str(e))
            return []

        txt_records = []
        for val in result:
            # remove quotes
            txt_records.append(val.to_text().replace('"', ""))

        return txt_records
