import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from creator.did_gen import DidGenerator
from jwcrypto.jwt import JWK


class DidGenTestCase(unittest.TestCase):

    def setUp(self):
        import os
        print(os.getcwd())
        self.did_gen = DidGenerator("creator/templates")

    def test_did_gen(self):
        # create rsa key pair
        private_rsa_key = rsa.generate_private_key(
            public_exponent=3,
            key_size=2048
        )
        public_rsa_key = JWK.from_pem(private_rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # create elliptic key pair
        private_ec_key = ec.generate_private_key(ec.SECP256R1())
        public_ec_key = JWK.from_pem(private_ec_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo))
        # run generator
        did_doc = self.did_gen.generate_did_document(issuer="did:web:example.com",
                                                     verification_methods={public_rsa_key, public_ec_key})


        # check results
        self.assertEqual(["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
                         did_doc['@context'])

        vm_rsa = None
        vm_ec = None
        for vm in did_doc['verificationMethod']:
            if str(vm["id"]).startswith("did:web:example.com#JWK2020-RSA-key"):
                vm_rsa = vm
            elif str(vm["id"]).startswith("did:web:example.com#JWK2020-EC-key"):
                vm_ec = vm

        self.assertEqual("JsonWebKey2020", vm_rsa["type"])
        self.assertEqual("did:web:example.com", vm_rsa["controller"])
        self.assertEqual("RSA", vm_rsa["publicKeyJwk"]["kty"])
        self.assertEqual("Aw", vm_rsa["publicKeyJwk"]["e"])

        self.assertEqual("JsonWebKey2020", vm_ec["type"])
        self.assertEqual("did:web:example.com", vm_ec["controller"])
        self.assertEqual("EC", vm_ec['publicKeyJwk']["kty"])
        self.assertEqual("P-256", vm_ec['publicKeyJwk']["crv"])


if __name__ == '__main__':
    unittest.main()
