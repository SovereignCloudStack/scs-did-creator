import base64
import datetime
import unittest
from unittest.mock import call, mock_open, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (RSAPrivateKey,
                                                           RSAPublicKey)
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from jwcrypto.jwt import JWK

from creator import did_gen


class DidGenTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # create private keys
        cls.priv_key_1 = _create_private_rsa_key()
        cls.priv_key_2 = _create_private_ec_key()
        # cls.priv_key_2 = _create_private_rsa_key()

        # create public keys
        cls.pub_key_1 = cls.priv_key_1.public_key()
        cls.pub_key_2 = cls.priv_key_2.public_key()

        cls.cert_1 = _create_certificate(issuer='1.example.com', subject='1.example.com', priv_key=cls.priv_key_1,
                                         pub_key=cls.pub_key_1)
        cls.cert_2 = _create_certificate(issuer='1.example.com', subject='2.example.com', priv_key=cls.priv_key_1,
                                         pub_key=cls.pub_key_2)

    @patch("creator.did_gen.open", create=True)
    def test_did_gen_keys(self, mocked_open):
        rsa_key_pub_bytes = self.priv_key_1.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_rsa_key = JWK.from_pem(rsa_key_pub_bytes)
        ec_key_pub_bytes = self.priv_key_2.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_ec_key = JWK.from_pem(ec_key_pub_bytes)

        # mock methods
        mocked_open.side_effect = [
            mock_open(read_data=rsa_key_pub_bytes).return_value,
            mock_open(read_data=ec_key_pub_bytes).return_value]

        # run generator
        did_doc = did_gen.generate_did_document(
            issuer="did:web:example.com",
            verification_methods=[did_gen.VerificationMethod(path="/foo/bar/rsa"),
                                  did_gen.VerificationMethod(path="/foo/bar/ec")])

        # check results
        # c = mocked_open.calls()
        # mocked_open.assert_has_calls([call("/foo/bar/rsa"), call("/foo/bar/ec")])
        self.assertEqual(["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
                         did_doc['@context'])
        self.assertEqual("did:web:example.com", did_doc['id'])

        for vm in did_doc['verificationMethod']:
            self.assertEqual("https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
                             vm['@context'])
            if str(vm["id"]).startswith("did:web:example.com#JWK2020-RSA"):
                vm_rsa = vm
            elif str(vm["id"]).startswith("did:web:example.com#JWK2020-EC"):
                vm_ec = vm

        self.assertEqual("JsonWebKey2020", vm_rsa["type"])
        self.assertEqual("did:web:example.com", vm_rsa["controller"])
        self.assertEqual("RSA", vm_rsa["publicKeyJwk"]["kty"])
        self.assertEqual(public_rsa_key['e'], vm_rsa["publicKeyJwk"]["e"])
        self.assertEqual(public_rsa_key['n'], vm_rsa["publicKeyJwk"]["n"])

        self.assertEqual("JsonWebKey2020", vm_ec["type"])
        self.assertEqual("did:web:example.com", vm_ec["controller"])
        self.assertEqual("EC", vm_ec['publicKeyJwk']["kty"])
        self.assertEqual("P-256", vm_ec['publicKeyJwk']["crv"])
        self.assertEqual(public_ec_key['x'], vm_ec['publicKeyJwk']["x"])
        self.assertEqual(public_ec_key['y'], vm_ec['publicKeyJwk']["y"])

    @patch("requests.get")
    @patch("creator.did_gen.open", create=True)
    def test_did_gen_certs(self, mocked_open, mocked_get):
        rsa_key_pub_bytes = self.priv_key_1.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_rsa_key = JWK.from_pem(rsa_key_pub_bytes)
        ec_key_pub_bytes = self.priv_key_2.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_ec_key = JWK.from_pem(ec_key_pub_bytes)

        # mock methods
        data = self.cert_2.public_bytes(encoding=Encoding.PEM).decode() + self.cert_1.public_bytes(encoding=Encoding.PEM).decode()
        mocked_open.side_effect = [
            mock_open(read_data=data).return_value]
        mocked_get.return_value.ok = True
        mocked_get.return_value.text = self.cert_1.public_bytes(encoding=Encoding.PEM).decode()

        # run generator
        did_doc = did_gen.generate_did_document(
            issuer="did:web:example.com",
            verification_methods=[did_gen.VerificationMethod(path="/foo/bar/rsa", x509=True),
                                  did_gen.VerificationMethod(path="http://foo/bar/ec", x509=True)])

        # check results
        self.assertEqual(["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
                         did_doc['@context'])
        self.assertEqual("did:web:example.com", did_doc['id'])

        self.assertEqual("did:web:example.com#JWK2020-X509-0", did_doc['verificationMethod'][0]["id"])
        self.assertEqual("https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
                         did_doc['verificationMethod'][0]['@context'])
        self.assertEqual("JsonWebKey2020", did_doc['verificationMethod'][0]["type"])
        self.assertEqual("did:web:example.com", did_doc['verificationMethod'][0]["controller"])
        self.assertEqual("EC", did_doc['verificationMethod'][0]['publicKeyJwk']["kty"])
        self.assertEqual("P-256", did_doc['verificationMethod'][0]['publicKeyJwk']["crv"])
        self.assertEqual(public_ec_key['x'], did_doc['verificationMethod'][0]['publicKeyJwk']["x"])
        self.assertEqual(public_ec_key['y'], did_doc['verificationMethod'][0]['publicKeyJwk']["y"])
        self.assertEqual([base64.b64encode(self.cert_2.public_bytes(encoding=Encoding.DER)).decode(),
                         base64.b64encode(self.cert_1.public_bytes(encoding=Encoding.DER)).decode()],
                         did_doc['verificationMethod'][0]["publicKeyJwk"]["x5c"])

        self.assertEqual("did:web:example.com#JWK2020-X509-1", did_doc['verificationMethod'][1]["id"])
        self.assertEqual("https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
                         did_doc['verificationMethod'][1]['@context'])
        self.assertEqual("JsonWebKey2020", did_doc['verificationMethod'][1]["type"])
        self.assertEqual("did:web:example.com", did_doc['verificationMethod'][1]["controller"])
        self.assertEqual("RSA", did_doc['verificationMethod'][1]["publicKeyJwk"]["kty"])
        self.assertEqual(public_rsa_key['e'], did_doc['verificationMethod'][1]["publicKeyJwk"]["e"])
        self.assertEqual(public_rsa_key['n'], did_doc['verificationMethod'][1]["publicKeyJwk"]["n"])
        self.assertEqual("http://foo/bar/ec", did_doc['verificationMethod'][1]['publicKeyJwk']["x5u"])

    def test_get_encode_cert_der_strings(self):
        cert_1_der = base64.b64encode(self.cert_1.public_bytes(encoding=Encoding.DER)).decode()
        cert_2_der = base64.b64encode(self.cert_2.public_bytes(encoding=Encoding.DER)).decode()
        cert_str = did_gen._get_encode_cert_der_strings_b64([self.cert_2, self.cert_1])
        self.assertEquals([cert_2_der, cert_1_der], cert_str)

    # def test_is_url(self):
    #    self.assertFalse(did_gen._is_url("/foo/bar"))
    #    self.assertTrue(did_gen._is_url("http://foo/bar"))
    #    self.assertTrue(did_gen._is_url("https://foo/bar"))

    @patch("requests.get")
    def test_get_cert_content(self, get_mock):
        cert_1_pem = self.cert_1.public_bytes(encoding=Encoding.PEM).decode()
        cert_2_pem = self.cert_2.public_bytes(encoding=Encoding.PEM).decode()

        # mock methods
        get_mock.return_value.ok = True
        get_mock.return_value.text = cert_2_pem + "\n" + cert_1_pem
        m_open = mock_open(read_data=(cert_2_pem + "\n" + cert_1_pem))
        with patch('builtins.open', m_open):
            certs_url = did_gen._get_cert_content("http://foo/bar/")
            self.assertEquals([self.cert_2, self.cert_1], certs_url)
            certs_path = did_gen._get_cert_content("/foo/bar/")
            self.assertEquals([self.cert_2, self.cert_1], certs_path)


def _create_certificate(issuer: str, subject, priv_key: RSAPrivateKey, pub_key: RSAPublicKey) -> x509.Certificate:
    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub_key)
    return builder.sign(
        private_key=priv_key, algorithm=hashes.SHA256(),
    )


def _create_private_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def _create_private_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


if __name__ == '__main__':
    unittest.main()
