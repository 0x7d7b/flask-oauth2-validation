from flask_oauth2_api import OAuth2Decorator
from flask import Flask, jsonify
from . import generate_test_token


def _expect_requires_token(app: Flask, introspect=False, scopes=[]):

    app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'

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
            'foo': 'bar'
        })
    })
    
    print(response.headers)

    _expect_valid_token(response)
