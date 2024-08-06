import unittest
from unittest.mock import mock_open, patch

from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import creator.cli as cli

CONFIG_DATA = {'issuer': ' did:web:example.com',
               'verification-methods': {
                   'keys': ['pub-key1.pem', 'pub-key2.pem'],
                   "x509s": ['path-to-cert', 'http://www.example.com']
               }}


class CliTestCase(unittest.TestCase):

    def setUp(self):
        # create rsa key pair
        private_key = rsa.generate_private_key(
            public_exponent=3,
            key_size=2048
        )
        self.public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @patch("creator.did_gen.generate_did_document")
    @patch("yaml.safe_load")
    def test_cli(self, mock_yaml_load, mock_did_gen):
        # mock method calls
        mock_yaml_load.return_value = CONFIG_DATA
        m_open = mock_open(read_data=self.public_key)
        mock_did_gen.return_value = "foo"

        with patch('builtins.open', m_open):
            # run tests
            runner = CliRunner()
            result = runner.invoke(
                cli.did_creator, "--config=config.template.yaml")

            # check results
            self.assertIsNone(result.exception)
            self.assertEqual(0, result.exit_code)
            self.assertEqual('"foo"\n', result.stdout)

        mock_yaml_load.assert_called_with(m_open())
        mock_did_gen.assert_called_once()


if __name__ == '__main__':
    unittest.main()
