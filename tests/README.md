# Tests

This directory contains unit tests for MREG CLI. The tests are written using the Pytest framework.

**NOTE:** All commands in this document assume the PWD is the repo root, *not* `<repo_root>/tests`.

## Setup

Development dependencies must be installed in order to run the tests:

```sh
pip install -e --upgrade '.[dev]'
```

## Running

The tests can be run manually with the following command:

```sh
pytest
```

Alternatively, to create a coverage report and view it in the browser:

```sh
just covhtml
```

*NOTE: this recipe requires [`just`](https://github.com/casey/just), which is an alternative to Make*




## Coverage

To create a test code coverage report, run the following:

```sh
coverage run --source=./mreg_cli -m pytest
coverage report
```

To create a more in-depth HTML coverage report, run the additional command:
```sh
coverage html
```

## Writing Tests

In order to write tests for functions that make use of MREG, we have 3 options:

1. Run a temporary MREG instance as a part of the test suite.
2. Mock the entire function.
3. Create a temporary HTTP server providing the same endpoints as the functions expect from MREG.

Option 1, while providing the most accurate results, requires a great deal of setup/teardown logic to make sure tests can run in arbitrary order, as they should not be able to modify state that can affect other tests.

Option 2 is not accurate enough, and completely circumvents the entire networking aspect of the applicaton. We are not able to accurately test if requests are constructed properly and how the responses are parsed.

Option 3 is a compromise between the two former options, where we set up endpoints that reflect the actual MREG endpoints, while not having to worry about setup/teardown logic and application state. In order to facilitate the creation of this simulated server, we can use [`pytest-httpserver`](https://pypi.org/project/pytest-httpserver/) to set up temporary endpoints that expect certain requests and respond with the data of our choosing.

As such, option 3 should be preferred, and is indeed the way most unit tests for MREG CLI involving HTTP requests are written.


### Fixtures

Through the use of pytest fixtures, both our own and ones provided by `pytest-httpserver` such as the fixture [`pytest_httpserver.httpserver`](https://pytest-httpserver.readthedocs.io/en/latest/tutorial.html).

In order to set the value of `mreg_cli.util.mregurl` to the address used by the fixture, we shadow the original `httpserver` fixture with our own that sets the value of `mreg_cli.util.mregurl` before yielding the actual `pytest_httpserver.httpserver`.

See [`tests/conftest.py`](/tests/conftest.py) for more info.

