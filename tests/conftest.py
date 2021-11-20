from flask import Flask

import pytest
import requests_mock
import logging

_test_logger = logging.getLogger(__name__)


@pytest.fixture(scope='function')
def test_app():
    with requests_mock.Mocker() as mock:
        _register_mock_addresses(mock)
        yield _create_flask_app()
        try:
            _assert_request_history()
        except BaseException:
            # Just in case catch exceptions at teardown.
            pass


def _create_flask_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


def _assert_request_history(
    mock: requests_mock.Mocker
):
    assert _was_requested(
        mock,
        'GET https://issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server'
    )
    assert _was_requested(
        mock,
        'GET https://issuer.local/oauth2/keys'
    )


def _was_requested(
    mock: requests_mock.Mocker,
    uri: str
):
    for request_proxy in mock.request_history:
        if str(request_proxy) == uri:
            _test_logger.debug(f'Verified request: {uri}')
            return True
    return False


def _register_mock_addresses(
    mock: requests_mock.Mocker
):
    mock.get(
        'https://issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://issuer.local/oauth2/keys',
            'introspection_endpoint':
                'https://issuer.local/oauth2/introspect',
            'introspection_endpoint_auth_methods_supported': [
                'client_secret_basic',
                'client_secret_post'
            ]
        }
    )
    mock.get(
        'https://issuer.local/oauth2/keys',
        json={
            'keys': [
                {'kid': 'x'},
                {'kid': 'a'},
                {'kid': 'z'}
            ]
        }
    )
