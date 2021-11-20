import pytest
from flask import Flask, jsonify
from flask_oauth2_api import OAuth2Decorator
from time import sleep

from . import generate_test_token


def _expect_requires_token(
    app: Flask,
    introspect=False,
    scopes=[],
    issuer='https://issuer.local/oauth2'
):

    app.config['OAUTH2_ISSUER'] = issuer

    oauth2 = OAuth2Decorator(app)

    @app.errorhandler(Exception)
    def internal_server_error(e):
        return jsonify({'error': str(e)}), 500

    @app.route('/')
    @oauth2.requires_token(
        introspect=introspect,
        scopes=scopes
    )
    def test_me():
        return jsonify({
            'token': oauth2.token
        }), 200

    @app.route('/raise')
    @oauth2.requires_token(
        introspect=introspect,
        scopes=scopes
    )
    def raise_me():
        raise Exception('Exception from decorated method')

    return app.test_client()


def _expect_valid_token(response):
    assert 200 == response.status_code


def _expect_internal_server_error(response, msg):
    assert 500 == response.status_code


def _expect_insufficient_scope(response, scopes):

    assert 403 == response.status_code

    assert response.headers['WWW-Authenticate']
    assert 'Bearer ' + \
        'error="insufficient_scope" ' + \
        'scope="'+scopes+'"' \
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
            'scp': ['foo', 'bar']
        })
    })

    _expect_valid_token(response)


def test_valid_token_missing_scope(test_app):

    test_client = _expect_requires_token(test_app, scopes=['foo', 'bar'])

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
            'scp': ['foo']
        })
    })

    _expect_insufficient_scope(response, 'bar')


def test_valid_token_no_scopes(test_app):

    test_client = _expect_requires_token(test_app, scopes=['foo', 'bar'])

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
        })
    })

    _expect_insufficient_scope(response, 'bar foo')


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


def test_valid_token_introspected_unknown_auth(test_app):

    test_app.config['OAUTH2_CLIENT_ID'] = 'foo'
    test_app.config['OAUTH2_CLIENT_SECRET'] = 'bar'

    with pytest.raises(TypeError) as error:

        _expect_requires_token(
            test_app,
            introspect=True,
            issuer='https://unknown_introspection_auth.issuer.local/oauth2'
        )

        assert str(error.value) == \
            'The introspection auth methods are not supported: ' + \
            'client_secret_unknown'


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


def test_expired_token(test_app):

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
            'iat': 1,
            'exp': 2
        })
    })

    _expect_invalid_token(response, 'JWT Expired')


def test_invalid_token_unknown_pubkey(test_app):

    test_client = _expect_requires_token(
        test_app,
        issuer='https://unknown_pubkey.issuer.local/oauth2'
    )

    response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://unknown_pubkey.issuer.local/oauth2'
        })
    })

    _expect_invalid_token(response, 'Invalid token signature')


def test_decorated_method_raises_exception(test_app):

    test_client = _expect_requires_token(test_app)

    response = test_client.get('/raise', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2'
        })
    })

    _expect_internal_server_error(response, 'Exception from decorated method')


def test_valid_token_with_pubkey_refresh(test_app):

    test_app.config['OAUTH2_JWKS_UPDATE_INTERVAL'] = 1

    test_client = _expect_requires_token(test_app)

    first_response = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
        })
    })

    _expect_valid_token(first_response)

    sleep(1.2)

    second_response_caused_pubkey_reload = test_client.get('/', headers={
        'Authorization': 'Bearer ' + generate_test_token({
            'iss': 'https://issuer.local/oauth2',
        })
    })

    _expect_valid_token(second_response_caused_pubkey_reload)


# TODO: tests for:
# - tokens with invalid signature,
# - token with invalid base64 header (keyid lookup)
# - key update executor
