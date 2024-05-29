"""Script to generate DID documents for did:web.

(c) Anja Strunk <anja.strunk@cloudandheat.com>, 4/2024
SPDX-License-Identifier: EPL-2.0
"""

from typing import List

from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from jwcrypto.jwt import JWK
from cryptography import x509
import requests


@dataclass
class VerificationMethod():
    path: str
    x509: bool = False


class DidGenerator:
    CONTEXT = [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"]

    def generate_did_document(self, issuer: str, verification_methods: List[VerificationMethod]) -> dict:
        """ Return a DID document for given issuer and with given  verification methods as dict.

        :param issuer: did:web of issuer
        :type issuer: str
        :param verification_methods: List of verification method to be added to DID document.
        :type verification_methods: List of VerificationMethods
        :@return: DID document as dict
        :rtype dict
        """

        did_doc = dict()
        did_doc['@context'] = self.CONTEXT
        did_doc['id'] = issuer
        did_doc['verificationMethod'] = list()
        did_doc['assertionMethod'] = list()

        key_number = 0
        for m in verification_methods:
            if m.x509:
                # parse x509 certificate
                response = requests.get(m.path)
                if response.ok:
                    key_name = issuer + "#X509-JWK2020-" + str(key_number)
                    cert = x509.load_pem_x509_certificates(response.text.encode('utf-8'))[0]
                    key = JWK.from_pem(cert.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
                else:
                    raise requests.HTTPError(
                        'Could not retrieve x509 certificate from ' + m.path + ". (HTTP status code: " + response.status_code)
            else:
                # parse public key
                with open(m.path, mode="rb") as file:
                    key = JWK.from_pem(file.read())
                    if key.kty == "RSA":
                        key_name = issuer + "#RSA-JWK2020-key-" + str(key_number)
                    elif key.kty == "EC":
                        key_name = issuer + "#EC-JWK2020-key-" + str(key_number)
                    else:
                        raise ValueError("Unsupported JSON Web Key type: " + key.kty + " found.")

            method = dict()
            method["@context"] = "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/"
            method['id'] = key_name
            method['type'] = "JsonWebKey2020"
            method['controller'] = issuer
            method['publicKeyJwk'] = key.export(as_dict=True)

            if m.x509:
                method['publicKeyJwk']['x5u'] = m.path
            did_doc['verificationMethod'].append(method)
            did_doc['assertionMethod'].append(key_name)

            key_number += 1

        return did_doc
