# scs-did-creator

Tools for managing creation of did:web for SCS conformant clouds.

## User Guide

We recommend to run scs-did-creator within a [python virtual environment](https://docs.python.org/3/library/venv.html)

Install dependencies

```shell
pip install -r requirements.txt
```

DID creator generates a DID document. Mandatory content for DID document such as issuer and verification methods are taken from `config.yaml`.

```yaml
issuer: "did:web:example.com"
verification-methods:
  - "/example1.pem.pub"
  - "/example2.pem.pub"
```

Attribute `issuer` defines issuer of DID document, which is the DID itself. scs-did-creator does support did:web only.
Attribute `verification-methods` refers to a list of public key files, used as verification method in DID document. scs-did-creator does support [RSA keys](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) and [EC keys](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) , only.

Currently, all verification methods are set as `assertionMethod`, e.i. can be used to verify [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) issued by `issuer`.

scs-did-creator is looking vor `config.yaml` in folder `/etc/scs-did-creator/`. You can specify our own configuration file using parameter `--config`

Run scs-did-creator

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

scs-did-creator uses [jinja templates](https://jinja.palletsprojects.com/en/3.1.x/) to generate DID document.

### Running unit tests

First, install the test dependencies in addition to the main dependencies into your virtualenv as described above under "Quick Start Guide":

`pip install -r test-requirements.txt`

Then, tests can be run with:

`python3 -m pytest`

To run tests with code coverage, use

`python -m pytest --cov`

### Updating the dependency pins

We pin dependencies with `pip-compile` from [pip-tools](https://pypi.org/project/pip-tools/), which can be installed with:

`pip install pip-tools`

If you change one of the `*.in` files, you need to regenerate the concrete `requirements.txt` files as follows (the order is important):

`pip-compile requirements.in`
`pip-compile test-requirements.in`

By default, `pip-compile` doesn't update the pinned versions. This can be changed by adding the `--upgrade` flag to the above invocations:

`pip-compile --upgrade requirements.in`
`pip-compile --upgrade test-requirements.in`

Whenever the concrete `requirements.txt` file change you also shouldn't forget to re-run the `pip install -r ...` steps again.
