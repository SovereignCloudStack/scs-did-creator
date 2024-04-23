# scs-did-creator
Tools for managing creation of did:web for SCS conformant clouds.


## User Guide



## Developers Guide


### Running unit tests

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