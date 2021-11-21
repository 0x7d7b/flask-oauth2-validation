# Install

    pip install .

# Test

    pip install -e .[test]
    pytest -v --cov=flask_oauth2_api tests/
    # Coverage visualized in vscode using "Code Coverage" extension
    coverage-lcov

# TODO

- pydoc everywhere -> as good as if I would publish it
- travis CI with test execution?
- coveralls github actions?
- render documentation site?
- fix minimal required dependency versions