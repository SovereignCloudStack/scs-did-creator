"""Script to generate DID documents fort did:web method.

(c) Anja Strunk <anja.sturnk@cloudandheat.com>, 4/2024
SPDX-License-Identifier: EPL-2.0
"""
import json

import click
import yaml

from creator import did_gen

DEFAULT_CONFIG_FILE = "/etc/scs-did-gen/config.yaml"


@click.command()
@click.option("--config", help="Configuration file for DID generator")
@click.option("--output-file", help="Output file - default stdout")
def did_creator(output_file, config):
    """Generates DID document for given DID and as set of verification methods defined in configuration file."""
    if not config:
        config = DEFAULT_CONFIG_FILE

    with open(config, "r") as config_file:
        config_dict = yaml.safe_load(config_file)
        veri_meths = list()

        # read out public keys
        if "keys" in config_dict['verification-methods']:
            for key in config_dict['verification-methods']['keys']:
                veri_meths.append(did_gen.VerificationMethod(path=key))
        # read out x509 certs
        if "x509s" in config_dict['verification-methods']:
            for cert in config_dict['verification-methods']['x509s']:
                veri_meths.append(did_gen.VerificationMethod(path=cert, x509=True))

        did_content = did_gen.generate_did_document(issuer=config_dict['issuer'], verification_methods=veri_meths)

        if output_file:
            with open(output_file, "w") as did_doc:
                did_doc.write(json.dumps(did_content, indent=2))
        else:
            print(json.dumps(did_content, indent=2))


if __name__ == "__main__":
    did_creator()
