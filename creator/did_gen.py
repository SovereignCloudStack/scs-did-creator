"""Script to generate DID documents for did:web.

(c) Anja Strunk <anja.strunk@cloudandheat.com>, 4/2024
SPDX-License-Identifier: EPL-2.0
"""

import base64
from dataclasses import dataclass
from typing import List

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto.jwt import JWK


@dataclass
class VerificationMethod:
    path: str
    x509: bool = False


CONTEXT = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"]
VM_CONTEXT = "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/"
VM_TYPE = "JsonWebKey2020"

def generate_did_document(issuer: str, verification_methods: List[VerificationMethod]) -> dict:
    """ Return a DID document for given issuer and with given  verification methods as dict.

    :param issuer: did:web of issuer
    :type issuer: str
    :param verification_methods: List of verification method to be added to DID document.
    :type verification_methods: List of VerificationMethods
    :@return: DID document as dict
    :rtype dict
    """

    did_doc = dict()
    did_doc['@context'] = CONTEXT
    did_doc['id'] = issuer
    did_doc['verificationMethod'] = list()
    did_doc['assertionMethod'] = list()

    for key_number, m in enumerate(verification_methods):
        if m.x509:
            # parse x509 certificate
            certs = _get_cert_content(m.path)
            key_name = issuer + "#JWK2020-X509-" + str(key_number)
            key = JWK.from_pem(certs[0].public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
        else:
            # parse public key
            with open(m.path, mode="rb") as file:
                key = JWK.from_pem(file.read())
                if key.kty == "RSA":
                    key_name = issuer + "#JWK2020-RSA-" + str(key_number)
                elif key.kty == "EC":
                    key_name = issuer + "#JWK2020-EC-" + str(key_number)
                else:
                    raise ValueError("Unsupported JSON Web Key type: " + key.kty + " found.")

        method = dict()
        method["@context"] = VM_CONTEXT
        method['id'] = key_name
        method['type'] = VM_TYPE
        method['controller'] = issuer
        method['publicKeyJwk'] = key.export(as_dict=True, private_key=False)

        if m.x509:
            if _is_url(m.path):
                method['publicKeyJwk']['x5u'] = m.path
            else:
                method['publicKeyJwk']['x5c'] = _get_encode_cert_der_strings_b64(certs)
        did_doc['verificationMethod'].append(method)
        did_doc['assertionMethod'].append(key_name)
    return did_doc


def _get_cert_content(path: str) -> str:
    if _is_url(path):
        # a URL was given and we have to download certificate
        response = requests.get(path)
        if response.ok:
            return x509.load_pem_x509_certificates(response.text.encode('utf-8'))
        else:
            raise requests.HTTPError(
                'Could not retrieve x509 certificate from ' + path + ". (HTTP status code: " + response.status_code)
    else:
        # a path is given and have to load from file
        with open(path, 'r') as file:
            return x509.load_pem_x509_certificates(file.read().encode("utf-8"))


def _is_url(path: str) -> bool:
    return path.startswith("http://") or path.startswith("https://")


def _get_encode_cert_der_strings_b64(cert_chain: x509.Certificate) -> List[str]:
    der_strings = list()
    for cert in cert_chain:
        der_strings.append(base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.DER)).decode())
    return der_strings
