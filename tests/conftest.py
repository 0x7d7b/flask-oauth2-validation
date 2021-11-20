from flask import Flask
import pytest
import requests_mock

from functional import test_jwk


@pytest.fixture(scope='function')
def test_app():
    with requests_mock.Mocker() as mock:
        _register_mock_addresses(mock)
        yield _create_flask_app()


def _create_flask_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


def _register_mock_addresses(
    mock: requests_mock.Mocker
):

    mock.get(
        'https://unsupported.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        status_code=404
    )

    mock.get(
        'https://missing_jwks.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'introspection_endpoint':
                'https://issuer.local/oauth2/introspect',
            'introspection_endpoint_auth_methods_supported': [
                'client_secret_basic',
                'client_secret_post'
            ]
        }
    )

    mock.get(
        'https://missing_introspection.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://issuer.local/oauth2/keys',
            'introspection_endpoint_auth_methods_supported': [
                'client_secret_basic',
                'client_secret_post'
            ]
        }
    )

    mock.get(
        'https://missing_introspection_auth.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://issuer.local/oauth2/keys',
            'introspection_endpoint':
                'https://issuer.local/oauth2/introspect',
        }
    )

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
        'https://basic_introspection.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://issuer.local/oauth2/keys',
            'introspection_endpoint':
                'https://basic_introspection.issuer.local/oauth2/introspect',
            'introspection_endpoint_auth_methods_supported': [
                'client_secret_basic'
            ]
        }
    )

    mock.get(
        'https://issuer.local/oauth2/keys',
        json={
            'keys': [
                {'kid': 'x'},
                test_jwk,
                {'kid': 'z'}
            ]
        }
    )

    mock.get(
        'https://key_lookup_error.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://key_lookup_error.issuer.local/oauth2/keys',
        }
    )

    mock.get(
        'https://key_lookup_error.issuer.local/oauth2/keys',
        status_code=500
    )

    mock.get(
        'https://invalid_introspection.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://issuer.local/oauth2/keys',
            'introspection_endpoint':
                'https://invalid_introspection.issuer.local/oauth2/introspect',
            'introspection_endpoint_auth_methods_supported': [
                'client_secret_basic',
                'client_secret_post'
            ]
        }
    )

    mock.post(
        'https://invalid_introspection.issuer.local/oauth2/introspect',
        json={
            'active': False
        }
    )

    mock.post(
        'https://issuer.local/oauth2/introspect',
        json={
            'active': True
        }
    )

    mock.post(
        'https://basic_introspection.issuer.local/oauth2/introspect',
        json={
            'active': True
        }
    )

    mock.get(
        'https://introspection_error.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://issuer.local/oauth2/keys',
            'introspection_endpoint':
                'https://introspection_error.issuer.local/oauth2/introspect',
            'introspection_endpoint_auth_methods_supported': [
                'client_secret_basic',
                'client_secret_post'
            ]
        }
    )

    mock.post(
        'https://introspection_error.issuer.local/oauth2/introspect',
        status_code=500
    )

    mock.get(
        'https://unknown_auth.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://issuer.local/oauth2/keys',
            'introspection_endpoint':
                'https://unknown_auth.issuer.local/oauth2/introspect',
            'introspection_endpoint_auth_methods_supported': [
                'client_secret_unknown'
            ]
        }
    )

    mock.get(
        'https://unknown_pubkey.issuer.local/oauth2' +
        '/.well-known/oauth-authorization-server',
        json={
            'jwks_uri':
                'https://unknown_pubkey.issuer.local/oauth2/keys',
        }
    )

    mock.get(
        'https://unknown_pubkey.issuer.local/oauth2/keys',
        json={
            'keys': [
                {'kid': 'x'},
                {'kid': 'z'}
            ]
        }
    )
