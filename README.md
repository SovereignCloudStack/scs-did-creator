# scs-did-creator

Tools for managing creation of [DID](https://www.w3.org/TR/did-core/) documents for SCS conformant clouds. Currently, scs-did-creator supports [did:web](https://w3c-ccg.github.io/did-method-web/) only.

## Quick Start

### Installation

We recommend to run scs-did-creator within a [python virtual environment](https://docs.python.org/3/library/venv.html)

Install dependencies

```shell
pip install -r requirements.txt
```

### Pre-requisites

Bases on [DID specification](https://www.w3.org/TR/did-core/#dfn-did-documents): "...DID documents contain information associated with a DID. They typically express verification methods, such as cryptographic public keys, and services relevant to interactions with the DID subject..."

In context of Gaia-X, DID document contains at least one verification method to verify authorship of Gaia-X Credentials. scs-did-creator supports [RSA keys](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) and [EC keys](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) as verification methods, only. If not already exist, create a public-private key pair with [OpenSSL](https://developers.yubico.com/PIV/Guides/Generating_keys_using_OpenSSL.html)

### Configure scs-did-creator

Mandatory content for DID document such as issuer and verification methods are taken from `config.yaml`.

```yaml
issuer: "did:web:example.com"
verification-methods:
  - "/example1.pem.pub"
  - "/example2.pem.pub"
```

Attribute `issuer` defines issuer of DID document, which is the DID itself. scs-did-creator does support did:web only.
Attribute `verification-methods` refers to a list of public key files, set as verification method in generated DID document.
Currently, all verification methods are set as `assertionMethod`, i.e. used to verify [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) issued by `issuer`.

### Run scs-did-creator

Run scs-did-creator with configuration file, implicitly.

```shell
python3 -m creator.cli
```

Run scs-did-creator with own configuration file

```shell
python3 -m creator.cli --config=my-config.yaml
```

scs-did-creator will print generated DID document on screen. There is also an option to write it to an output file instead of stdout.

```shell
python3 -m creator.cli --output-file=my-did-document.json
```

## Developers Guide

scs-did-creator uses [jinja templates](https://jinja.palletsprojects.com/en/3.1.x/) to generate DID documents.

### Running unit tests

First, install the test dependencies in addition to the main dependencies into your virtualenv as described above under "Quick Start Guide":

```shell
pip install -r test-requirements.txt
```

Then, tests can be run with:

```shell
python3 -m pytest
```

To run tests with code coverage, use

```shell
python -m pytest --cov
```

### Updating the dependency pins

We pin dependencies with `pip-compile` from [pip-tools](https://pypi.org/project/pip-tools/), which can be installed with:

```shell
pip install pip-tools
```

If you change one of the `*.in` files, you need to regenerate the concrete `requirements.txt` files as follows (the order is important):

```shell
pip-compile requirements.in
pip-compile test-requirements.in
```

By default, `pip-compile` doesn't update the pinned versions. This can be changed by adding the `--upgrade` flag to the above invocations:

```shell
pip-compile --upgrade requirements.in
pip-compile --upgrade test-requirements.in
```

Whenever the concrete `requirements.txt` file change you also shouldn't forget to re-run the `pip install -r ...` steps again.
