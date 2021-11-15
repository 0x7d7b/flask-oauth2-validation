# Install

    pip install .

# Test

    pip install -e .[test]
    python -m pytest

# TODO


- make the token available to the decorated method
- pydoc everywhere -> as good as if I would publish it
- travis CI with test execution?
- render documentation site?
- fix minimal required dependency versions
- validate against scopes (in case of reference tokens scopes must be empty)

- write tests for the initialization
  - minimal working config with retrieving missing attributes from a mock metadata service
  - all other possible combinations and invalid ones (-> expected exceptions)