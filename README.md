# Install

    pip install .

# Test

    pip install -e .[test]
    pytest --cov=flask_oauth2_api

# TODO

- metadata request required for introspect auth method support validation
    - completely switch to metadata support only?
- write (mock) tests with a running flask instance

- pydoc everywhere -> as good as if I would publish it
- travis CI with test execution?
- render documentation site?
- fix minimal required dependency versions