from flask_oauth2_api import OAuth2Decorator
from flask import Flask, jsonify
from . import generate_test_token
import pytest


def _expect_requires_token(
    app: Flask,
    introspect=False,
    scopes=[],
    issuer='https://issuer.local/oauth2'
):

    app.config['OAUTH2_ISSUER'] = issuer

    oauth2 = OAuth2Decorator(app)

    @app.route('/')
    @oauth2.requires_token(
        introspect=introspect,
        scopes=scopes
    )
    def test_me():
        return jsonify({
            'token': oauth2.token
        }), 200

    return app.test_client()


def _expect_valid_token(response):
    assert 200 == response.status_code


def _expect_insufficient_scope(response, msg):

    assert 403 == response.status_code

    assert response.headers['WWW-Authenticate']
    assert 'Bearer ' + \
        'error="insufficient_scope" ' + \
        'scope="'+msg+'"' \
        == response.headers['WWW-Authenticate']


def _expect_invalid_token(response, msg):

    assert 401 == response.status_code

    assert response.headers['WWW-Authenticate']
    assert 'Bearer ' + \
        'error="invalid_token" ' + \
        'error_description="'+msg+'"' \
        == response.headers['WWW-Authenticate']


def _expect_invalid_request(response, msg):

    assert 400 == response.status_code

    assert response.headers['WWW-Authenticate']
    assert 'Bearer ' + \
        'error="invalid_request" ' + \
        'error_description="'+msg+'"' \
        == response.headers['WWW-Authenticate']


def test_request_without_headers(test_app):
    test_client = _expect_requires_token(test_app)

    response = test_client.get('/')

    _expect_invalid_request(response, 'Authorization header missing')


def test_request_with_empty_authorization_header(test_app):

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/', headers={
        'Authorization': ''
    })

    _expect_invalid_request(response, 'Authorization header missing')


def test_request_missing_token(test_app):

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/', headers={
        'Authorization': 'Bearer'
    })

    _expect_invalid_request(response, 'Bearer access token missing')


def test_request_wrong_auth(test_app):

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/', headers={
        'Authorization': 'Basic asdfasdfasdf'
    })

    _expect_invalid_request(response, 'Bearer access token missing')


def test_request_wrong_syntax(test_app):

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/', headers={
        'Authorization': 'Bearer fooooobaaaar'
    })

    _expect_invalid_request(response, 'Invalid token format')


def test_valid_token(test_app):

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
            'aud': 'api://default',
        })
    })

    _expect_valid_token(response)


def test_invalid_token_pubkey_lookup_error(test_app):

    with pytest.raises(TypeError) as error:

        _expect_requires_token(
            test_app,
            issuer='https://key_lookup_error.issuer.local/oauth2'
        )

        assert str(error.value) ==  \
            'Cannot request public keys from ' + \
            'https: // key_lookup_error.issuer.local/oauth2/keys'


def test_invalid_audience(test_app: Flask):

    test_app.config['OAUTH2_AUDIENCE'] = 'api://default'

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
            'aud': 'non-matching-audience',
        })
    })

    _expect_invalid_token(response, 'Invalid token audience')


def test_invalid_issuer(test_app: Flask):

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'other-issuer',
        })
    })

    _expect_invalid_token(response, 'Invalid token issuer')


def test_valid_token_with_scopes(test_app):

    test_client = _expect_requires_token(test_app, scopes=['foo', 'bar'])

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
            'aud': 'api://default',
            'scp': ['foo', 'bar']
        })
    })

    _expect_valid_token(response)


def test_valid_token_missing_scope(test_app):

    test_client = _expect_requires_token(test_app, scopes=['foo', 'bar'])

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
            'aud': 'api://default',
            'scp': ['foo']
        })
    })

    _expect_insufficient_scope(response, 'bar')


def test_valid_token_introspected_post(test_app):

    test_app.config['OAUTH2_CLIENT_ID'] = 'foo'
    test_app.config['OAUTH2_CLIENT_SECRET'] = 'bar'

    test_client = _expect_requires_token(
        test_app,
        introspect=True
    )

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
        })
    })

    _expect_valid_token(response)


def test_valid_token_introspected_basic(test_app):

    test_app.config['OAUTH2_CLIENT_ID'] = 'foo'
    test_app.config['OAUTH2_CLIENT_SECRET'] = 'bar'

    test_client = _expect_requires_token(
        test_app,
        introspect=True,
        issuer='https://basic_introspection.issuer.local/oauth2'
    )

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://basic_introspection.issuer.local/oauth2',
        })
    })

    _expect_valid_token(response)


def test_invalid_token_introspection_error(test_app):

    test_app.config['OAUTH2_CLIENT_ID'] = 'foo'
    test_app.config['OAUTH2_CLIENT_SECRET'] = 'bar'

    test_client = _expect_requires_token(
        test_app,
        introspect=True,
        issuer='https://introspection_error.issuer.local/oauth2'
    )

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://introspection_error.issuer.local/oauth2',
        })
    })

    _expect_invalid_token(response, 'Invalid token')


def test_invalid_token_introspected(test_app):

    test_app.config['OAUTH2_CLIENT_ID'] = 'foo'
    test_app.config['OAUTH2_CLIENT_SECRET'] = 'bar'

    test_client = _expect_requires_token(
        test_app,
        introspect=True,
        issuer='https://invalid_introspection.issuer.local/oauth2'
    )

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://invalid_introspection.issuer.local/oauth2',
        })
    })

    _expect_invalid_token(response, 'Invalid token')


def test_introspect_config_missing(test_app):

    test_client = _expect_requires_token(
        test_app,
        introspect=True
    )

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
        })
    })

    _expect_invalid_token(response, 'Invalid configuration')
