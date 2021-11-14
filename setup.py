from setuptools import find_packages, setup

import flask_oauth2_api

setup_dependencies = [
    'flake8'
]

install_dependencies = [
    'jwt',
    'requests',
    'flask-executor'
]

test_dependencies = [
    'pytest',
    'flask'
]

setup(
    name='flask-oauth2-api',
    packages=find_packages(),
    version=flask_oauth2_api.__version__,
    author=flask_oauth2_api.__author__,
    author_email=flask_oauth2_api.__mail__,
    url=flask_oauth2_api.__homepage__,
    license=flask_oauth2_api.__license__,
    description='Flask OAuth2 access token verification for resource servers',
    long_description=(
        'Verifies OAuth2 tokens for resource servers.'
        'Handles reference tokens as well as self-encoded JWT tokens.'
        'Supports introspection endpoints and public key verification.'
        'Supports auto discovery of introspection and jwks endpoints'
        'by using authorization server metadata endpoints (RFC-8414)'
    ),
    include_package_data=True,
    setup_requires=setup_dependencies,
    install_requires=install_dependencies,
    test_suite="tests",
    tests_require=test_dependencies,
    extras_require={
        'test': test_dependencies
    }
)
