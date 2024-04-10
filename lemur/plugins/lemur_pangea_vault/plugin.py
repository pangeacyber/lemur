"""
.. module: lemur.plugins.lemur_atlas_redis.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Jay Zarfoss
"""
import requests
import json

from flask import current_app
from lemur.plugins.bases import IssuerPlugin
import lemur.plugins.lemur_pangea_vault as vault
from lemur.common.utils import validate_conf
from lemur.certificates.models import Certificate


class PangeaVaultIssuerPlugin(IssuerPlugin):
    title = "PangeaVaultIssuer"
    slug = "pangea-vault-issuer"
    description = "Pangea Vault issuer plugin"
    version = vault.VERSION

    author = "H. Andres Tournour"
    author_url = "https://github.com/pangea-andrest"

    def __init__(self, *args, **kwargs):
        """Initialize source with appropriate details."""
        required_vars = [
            "PANGEA_VAULT_AUTH_TOKEN",
            "PANGEA_VAULT_DOMAIN",
        ]
        validate_conf(current_app, required_vars)

        self.vault_base_api = current_app.config.get("PANGEA_VAULT_DOMAIN")
        # self.vault_base_api = "https://vault-gea-13673.dev.aws.pangea.cloud"
        self.token = current_app.config.get("PANGEA_VAULT_AUTH_TOKEN")
        print("base API:", self.vault_base_api)

        super().__init__(*args, **kwargs)

    def widget(self, request, group, **kwargs):
        return "<p>Absolutely useless widget</p>"

    def _algorithm_lemur_to_pangea(self, signing_algorithm: str) -> str:
        if signing_algorithm == "sha256WithRSA":
            return "RSA-4096-SHA256"
        elif signing_algorithm == "sha256WithECDSA":
            return "ECDSA-SHA256"
        elif signing_algorithm == "sha384WithECDSA":
            return "ECDSA-SHA384"
        elif signing_algorithm == "sha512WithECDSA":
            return "ECDSA-SHA512"
        else:
            raise ValueError(f"Signing algorithm [{signing_algorithm}] not supported")

    def _key_type_lemur_to_pangea(self, key_type: str) -> str:
        if key_type == "RSA4096":
            return "RSA-4096-SHA256"
        if key_type == "RSA2048":
            return "RSA-2048-SHA256"
        elif key_type == "ECCPRIME256V1":
            return "ECDSA-SHA256"
        elif key_type == "ECCSECP384R1":
            return "ECDSA-SHA384"
        else:
            raise ValueError(f"Key type [{key_type}] not supported")

    def create_certificate(self, csr, issuer_options):
        # {'replacements': [Certificate(name=TimeTestAuthority5)],
        # 'rotation_policy': RotationPolicy(days=30, name=default),
        # 'owner': 'secure@example.net', 'location': 'Los Gatos', 'notify': True, 'destinations': [], 'replaces': [Certificate(name=TimeTestAuthority5)], 'roles': [], 'state': 'California', 'notifications': [Notification(label=DEFAULT_SECURE_30_DAY), 
        # Notification(label=DEFAULT_SECURE_15_DAY), Notification(label=DEFAULT_SECURE_2_DAY)], 'organizational_unit': 'Operations', 'extensions': {'sub_alt_names': {'names': <SubjectAlternativeName(<GeneralNames([<DNSName(value='*.test.example.net')>, <DNSName(value='www.test.example.net')>])>)>}}, 
        # 'key_type': 'ECCPRIME256V1', 'common_name': 'test.example.net', 'country': 'US', 'dns_provider': None, 'organization': 'Netflix, Inc.', 'description': '', 'authority': 

        print(f"create_certificate issuer_options: {issuer_options}")
        print(f"create_certificate csr: {csr}")

        exp = issuer_options["validity_end"].format("YYYY-MM-DDTHH:mm:ss.SSSSSS") + "Z"

        issuer_id = next(role for role in issuer_options["authority"].role if role.name.startswith("pvi_")).name
        algorithm = self._key_type_lemur_to_pangea(issuer_options["key_type"])

        data = {
            "csr": csr,
            "issuer_item_id": issuer_id,
            "algorithm": algorithm,
            "folder": "/lemur/csr/",
            "expiration": exp,
        }
        print("Create certificate. Data: ", json.dumps(data))
        resp = requests.post(
            f"{self.vault_base_api}/v1/pki/generate/csr",
            json=data,
            headers=self._headers(),
        )

        print("Create certificate. Resp:", resp.text)
        resp.raise_for_status()
        resp_data = resp.json()["result"]
        print("Create certificate. Result:", json.dumps(resp_data))
        id = resp_data["id"]
        print(f"Pangea Vault Cert id: {id}")
        return resp_data["certificate"], resp_data["trust_chain"], id

    def _headers(self):
        headers = {
            "User-Agent": "lemur-vault-plugin",
            "Authorization": f"Bearer {self.token}",
        }
        return headers

    def create_authority(self, options):
        # {'country': 'US', 'description': 'test', 'first_serial': 1,
        # 'organizational_unit': 'Operations', 'location': 'Los Gatos',
        # 'name': 'TimeTestAuthority1', 'state': 'California', 'sensitivity':
        # 'medium', 'signing_algorithm': 'sha256WithRSA', 'key_type': 'RSA2048',
        # 'owner': 'secure@example.com', 'validity_end': <Arrow [2044-02-20T15:31:36.774882+00:00]>,
        # 'extensions': {'sub_alt_names': {'names': <SubjectAlternativeName(<GeneralNames([])>)>}, 'custom': []}, 
        # 'plugin': {'slug': 'pangea-vault-issuer', 'plugin_object': <lemur.plugins.pangea_vault.plugin.PangeaVaultIssuerPlugin object at 0x113e07a60>, 'plugin_options': []}, 
        # 'common_name': 'AcommonName', 'validity_start': <Arrow [2024-02-20T15:31:36.774882+00:00]>, 'organization': 'Netflix',
        # 'type': 'root', 'validity_years': 20, 'creator': User(username=lemur)}

        print(f"On: create_authority. Options: {options}")

        exp = options["validity_end"].format("YYYY-MM-DDTHH:mm:ss.SSSSSS") + "Z"
        subj = ",".join(
            f"{code}={options[fld]}"
            for code, fld in (
                ("C", "country"),
                ("ST", "state"),
                ("L", "location"),
                ("O", "organization"),
                ("OU", "organizational_unit"),
                ("CN", "common_name")
            )
            if fld in options
        )

        algorithm = self._algorithm_lemur_to_pangea(options["signing_algorithm"])
        data = {
            "type": "ca",
            "name": options["name"],
            "algorithm": algorithm,
            "subject": subj,
            "expiration": exp,
            "metadata": {
                "description": options["description"],
                "creator": options["creator"].username,
            },
            "folder": "/lemur/ca/",
            "tags": ["lemur"]
        }

        print("data: ", json.dumps(data))
        resp = requests.post(
            f"{self.vault_base_api}/v1/pki/generate",
            json=data,
            headers=self._headers(),
        )

        print(f"On: create_authority. resp text: {resp.text}")

        resp.raise_for_status()
        item_id = resp.json()["result"]["id"]
        cert = resp.json()["result"]["certificate"]
        print(f"Pangea Vault CA id: {item_id}")
        role = {"username": options["creator"].username, "password": "", "name": item_id}
        print("Certificate: ", json.dumps(cert))
        return cert, "", [role]

    def revoke_certificate(self, certificate: Certificate, reason):
        print("revoke_certificate. Certificate: ", certificate.__dict__, reason)
        print("Cert external_id: ", certificate.external_id)
        data = {
            "id": certificate.external_id,
            "state": "deactivated"
        }
        print("data: ", data)
        resp = requests.post(
            f"{self.vault_base_api}/v1/state/change",
            json=data,
            headers=self._headers(),
        )
        print(f"On: revoke_certificate. resp text: {resp.text}")
        resp.raise_for_status()

    def deactivate_certificate(self, certificate: Certificate):
        print("deactivate_certificate. Certificate: ", certificate._dict__)
        print("Cert external_id: ", certificate.external_id)
        data = {
            "id": certificate.external_id,
            "state": "suspended"
        }
        print("data: ", data)
        resp = requests.post(
            f"{self.vault_base_api}/v1/state/change",
            json=data,
            headers=self._headers(),
        )
        print(f"On: deactivate_certificate. resp text: {resp.text}")
        resp.raise_for_status()
