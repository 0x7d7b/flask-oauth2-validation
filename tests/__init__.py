from flask import Flask

import pytest
import requests_mock
import logging

_test_logger = logging.getLogger(__name__)

mocked_keys = {
    'x': {'kid': 'x'},
    'a': {'kid': 'a'},
    'z': {'kid': 'z'}
}

_test_app_kwargs = {}


@pytest.fixture
def test_app():
    with requests_mock.Mocker() as mock:
        def wrapper(**kwargs):
            global _test_app_kwargs
            _test_app_kwargs = kwargs
            _register_mock_addresses(mock, **kwargs)
            return _create_flask_app()
        yield wrapper
        _assert_request_history(mock, **_test_app_kwargs)


def _create_flask_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


def _assert_request_history(
    mock: requests_mock.Mocker,
    meta_data=False,
    jwks_uri=False
):
    if meta_data:
        assert _was_requested(
            mock,
            'GET https://issuer.local/oauth2/.well-known/oauth-authorization-server'
        )
    if jwks_uri:
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
    mock: requests_mock.Mocker,
    meta_data=False,
    jwks_uri=False
):
    if meta_data:
        mock.get(
            'https://issuer.local/oauth2/.well-known/oauth-authorization-server',
            json={
                'jwks_uri': 'https://issuer.local/oauth2/keys'
            }
        )
    if jwks_uri:
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
