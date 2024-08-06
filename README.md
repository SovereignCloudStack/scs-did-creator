# scs-did-creator

Tools for managing creation of [DID](https://www.w3.org/TR/did-core/) documents for SCS conformant clouds. Currently, scs-did-creator supports [did:web](https://w3c-ccg.github.io/did-method-web/) method only.

## Quick Start

### Installation

We recommend to run scs-did-creator within a [python virtual environment](https://docs.python.org/3/library/venv.html)

Install dependencies

```shell
pip install -r requirements.txt
```

### Pre-requisites

Bases on [DID specification](https://www.w3.org/TR/did-core/#dfn-did-documents): "...DID documents contain information associated with a DID. They typically express verification methods, such as cryptographic public keys, and services relevant to interactions with the DID subject..."

There a several types of verification methods, such as [JsonWebKey2020](https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020) (JWK) or [EcdsaSecp256k1VerificationKey2019](https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/). A complete list of supported types can be found in [DID Spec Registry](https://www.w3.org/TR/did-spec-registries/).

**Note**: SCS scs-did-creator supports JWK, only.

Public-Private JWK key pairs JWK could by different cryptographic algorithms.

**Note**: SCS scs-did-creator supports [RSA keys](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) and [EC keys](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography), only.

You need at lest one private-public key pair to generate DID document. If ypu do not have one, create a public-private key pair with [OpenSSL](https://developers.yubico.com/PIV/Guides/Generating_keys_using_OpenSSL.html).

### Configure scs-did-creator

Mandatory content for DID document is are taken from `config.yaml`.

```yaml
issuer: "did:web:example.com"
verification-methods:
  keys:
    - "/example1.pem.pub"
    - "/example2.pem.pub"
  x509s:
    - "/cert1.pem"
    - "https://www.example.com/cert2.pem" 
```

The following attribute MUST be set:

- `issuer`: Issuer of DID document, which is the DID itself.
- `verification-methods`: List of public keys used as verification methods in DID document to be generated. scs-did-creator sets JWK as verification method. JWK is formatted according to [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517#section-4) as verification method only. At least one verification method MUST be set:
  
 - `key`: Absolute file path to private key file. Using this setting adds JWK as verification method expressed by parameters `n` and `e`, only
 - `x509`: Either path or url to X.509 certificate chain. Generator uses public key being referred by first certificate as verification method. Specifying certificate as file path adds [`x5c`](https://datatracker.ietf.org/doc/html/rfc7517#section-4.7), using an URL, adds [`x5u`](https://datatracker.ietf.org/doc/html/rfc7517#section-4.6) parameter to JWK format.

**Note**: Each entry in `verification-method` will adds an additional verification method to DID document. Eg. the following configuration file, will result in a DID document with three verification methods.

```yaml
issuer: "did:web:example.com"
verification-methods:
  keys:
    - "/example1.pem.pub"
  x509s:
    - "https://www.example.com/cert2.pem" 
```

```json

{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:example.com",
  "verificationMethod": [
    {
      "@context": "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
      "id": "did:did:web:example.com#JWK2020-RSA-0",
      "type": "JsonWebKey2020",
      "controller": "did:did:web:example.com",
      "publicKeyJwk": {
        "kty": "RSA",
        "kid": "q7Br89MDU0pbnBELpEwMHuy8KmOZXoZLIVb3gVGN9So",
        "n": "l2p0GOipSrw8CPOxPfRUohkB_ritC4wwNsH1A8eilZ1ntEfjCFsuxGutoEFXq8ge5dyvmmeZu5Ezt2crTJbS55_OFAeepsPIyO_O3JHJNtp5aNOv-0bJUVc5_6xLC5ucLUYtj5tzRimiaP5AM-uZCqIpG5VV8ELT1-HTaW9Bj-Ruajwm0MplGK3lZlpt1FAM7Rp4OAHyMiHDimw8X4qwgFIaj28YZqyIkB04Yc-jhl7_lHB0WRfVN---Lj9J-vCgKIfvCYlKWIwGgIr5FuElDnGv3uNFnTlcruWtBG0JzV8PLWJ0AGeWZWYsSca41Df9BvqVY24qi9JUH89FNqMnc_mNlX-G-49ap0c4L-kEQ6jCO3_tsqYsIMRWiuPeZ49d8o7kYZasXPuAvqLXCJK4BBGnXcBiqvfyrazWe0Yz_jC9MxdqXyakEf2RWmaPtna9JVH-Lx8eSHcvrX5FOSz2fPEwC_FCfM9gpO8TnUTq93gcXWuJtswChCryAtlmF3lC4DFdgzJxnqesrS1x0J2rqOl2anpQRCUa5m3om3y0gqQ3_XYqK1ezDbP3pRkeuwSS2e4HEPEZM6-euAK0G6TKA-EIO1Igb1F_EqeV_cOw5Jjxljj9IGzKrCZ4qXZX30sG0aMeCgGvreU2jGIDJzNrY7lM1SgXOFKffluI7nrvOzk",
        "e": "AQAB"
      }
    },
    {
      "@context": "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
      "id": "did:did:web:example.com#JWK2020-X509-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com",
      "publicKeyJwk": {
        "kty": "RSA",
        "kid": "q7Br89MDU0pbnBELpEwMHuy8KmOZXoZLIVb3gVGN9So",
        "n": "l2p0GOipSrw8CPOxPfRUohkB_ritC4wwNsH1A8eilZ1ntEfjCFsuxGutoEFXq8ge5dyvmmeZu5Ezt2crTJbS55_OFAeepsPIyO_O3JHJNtp5aNOv-0bJUVc5_6xLC5ucLUYtj5tzRimiaP5AM-uZCqIpG5VV8ELT1-HTaW9Bj-Ruajwm0MplGK3lZlpt1FAM7Rp4OAHyMiHDimw8X4qwgFIaj28YZqyIkB04Yc-jhl7_lHB0WRfVN---Lj9J-vCgKIfvCYlKWIwGgIr5FuElDnGv3uNFnTlcruWtBG0JzV8PLWJ0AGeWZWYsSca41Df9BvqVY24qi9JUH89FNqMnc_mNlX-G-49ap0c4L-kEQ6jCO3_tsqYsIMRWiuPeZ49d8o7kYZasXPuAvqLXCJK4BBGnXcBiqvfyrazWe0Yz_jC9MxdqXyakEf2RWmaPtna9JVH-Lx8eSHcvrX5FOSz2fPEwC_FCfM9gpO8TnUTq93gcXWuJtswChCryAtlmF3lC4DFdgzJxnqesrS1x0J2rqOl2anpQRCUa5m3om3y0gqQ3_XYqK1ezDbP3pRkeuwSS2e4HEPEZM6-euAK0G6TKA-EIO1Igb1F_EqeV_cOw5Jjxljj9IGzKrCZ4qXZX30sG0aMeCgGvreU2jGIDJzNrY7lM1SgXOFKffluI7nrvOzk",
        "e": "AQAB",
        "alg": "RS256",
        "x5u": "https://www.example.com/cert2.pem" 
      }
    }
  ],
  "assertionMethod": [
    "did:web:gaia-x.cloudandheat.com#JWK2020-RSA-0",
    "did:web:gaia-x.cloudandheat.com#JWK2020-X509-1"
  ]
}
```

### Run scs-did-creator

Run scs-did-creator with configuration file, implicitly. config.yaml MUST be placed in `/etc/scs-did-gen/config.yaml`

```shell
python3 -m creator.cli
```

Run scs-did-creator with configuration file, explicitly.

```shell
python3 -m creator.cli --config=my-config.template.yaml
```

scs-did-creator will print generated DID document on screen. There is also an option to write it to an output file instead of stdout.

```shell
python3 -m creator.cli --output-file=my-did-document.json
```

## Developers Guide

### Running unit tests

Install test dependencies in addition to the main dependencies into your virtualenv as described above under "Quick Start Guide":

```shell
pip install -r test-requirements.txt
```

Run tests:

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
