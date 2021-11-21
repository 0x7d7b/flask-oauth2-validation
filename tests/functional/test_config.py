from flask_oauth2_validation import OAuth2Decorator
import pytest
from . import mocked_keys


def test_missing_config(test_app):
    with pytest.raises(TypeError) as err:
        OAuth2Decorator(test_app)
    assert str(err.value) == 'An OAUTH2_ISSUER config property is required'


def test_no_metadata_support(test_app):
    with pytest.raises(TypeError) as err:
        test_app.config['OAUTH2_ISSUER'] = \
            'https://unsupported.issuer.local/oauth2'
        OAuth2Decorator(test_app)
    assert str(err.value) == \
        'Cannot request authorization server metadata: 404'


def test_missing_jwks_metadata(test_app):
    with pytest.raises(TypeError) as err:
        test_app.config['OAUTH2_ISSUER'] = \
            'https://missing_jwks.issuer.local/oauth2'
        OAuth2Decorator(test_app)
    assert str(err.value) == \
        'Cannot request authorization server metadata: ' + \
        'No attribute jwks_uri found in authorization ' + \
        'server metadata'


def test_missing_introspection_metadata(test_app):
    with pytest.raises(TypeError) as err:
        test_app.config['OAUTH2_ISSUER'] = \
            'https://missing_introspection.issuer.local/oauth2'
        test_app.config['OAUTH2_CLIENT_ID'] = 'foo-client'
        test_app.config['OAUTH2_CLIENT_SECRET'] = 'very-secure'
        OAuth2Decorator(test_app)
    assert str(err.value) == \
        'Cannot request authorization server metadata: ' + \
        'No attribute introspection_endpoint found in ' + \
        'authorization server metadata'


def test_missing_introspection_auth_metadata(test_app):
    with pytest.raises(TypeError) as err:
        test_app.config['OAUTH2_ISSUER'] = \
            'https://missing_introspection_auth.issuer.local/oauth2'
        test_app.config['OAUTH2_CLIENT_ID'] = 'foo-client'
        test_app.config['OAUTH2_CLIENT_SECRET'] = 'very-secure'
        OAuth2Decorator(test_app)
    assert str(err.value) == \
        'Cannot request authorization server metadata: ' + \
        'No attribute introspection_endpoint_auth_methods_supported ' + \
        'found in authorization server metadata'


def test_local_validation(test_app):
    test_app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    oauth2 = OAuth2Decorator(test_app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._jwks_uri == 'https://issuer.local/oauth2/keys'
    assert oauth2._issuer_public_keys == mocked_keys
    assert not oauth2._introspection_endpoint
    assert not oauth2._introspection_auth_method
    assert not oauth2._client_id
    assert not oauth2._client_secret
    assert not oauth2._jwks_update_interval
    assert not oauth2._executor


def test_local_validation_with_pubkey_reload(test_app):
    test_app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    test_app.config['OAUTH2_JWKS_UPDATE_INTERVAL'] = 1234
    oauth2 = OAuth2Decorator(test_app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._jwks_uri == 'https://issuer.local/oauth2/keys'
    assert oauth2._issuer_public_keys == mocked_keys
    assert oauth2._jwks_update_interval == 1234
    assert oauth2._executor
    assert not oauth2._introspection_endpoint
    assert not oauth2._introspection_auth_method
    assert not oauth2._client_id
    assert not oauth2._client_secret


def test_remote_validation(test_app):
    test_app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    test_app.config['OAUTH2_CLIENT_ID'] = 'foo-client'
    test_app.config['OAUTH2_CLIENT_SECRET'] = 'very-secure'
    oauth2 = OAuth2Decorator(test_app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._jwks_uri == 'https://issuer.local/oauth2/keys'
    assert oauth2._issuer_public_keys == mocked_keys
    assert oauth2._client_id == 'foo-client'
    assert oauth2._client_secret == 'very-secure'
    assert oauth2._introspection_endpoint == \
        'https://issuer.local/oauth2/introspect'
    assert oauth2._introspection_auth_method == 'client_secret_post'
    assert not oauth2._jwks_update_interval
    assert not oauth2._executor


def test_remote_validation_with_pubkey_reload(test_app):
    test_app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    test_app.config['OAUTH2_CLIENT_ID'] = 'foo-client'
    test_app.config['OAUTH2_CLIENT_SECRET'] = 'very-secure'
    test_app.config['OAUTH2_JWKS_UPDATE_INTERVAL'] = 1234
    oauth2 = OAuth2Decorator(test_app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._jwks_uri == 'https://issuer.local/oauth2/keys'
    assert oauth2._issuer_public_keys == mocked_keys
    assert oauth2._client_id == 'foo-client'
    assert oauth2._client_secret == 'very-secure'
    assert oauth2._introspection_endpoint == \
        'https://issuer.local/oauth2/introspect'
    assert oauth2._introspection_auth_method == 'client_secret_post'
    assert oauth2._jwks_update_interval == 1234
    assert oauth2._executor


def test_introspection_setup_without_secret(test_app):
    test_app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    test_app.config['OAUTH2_CLIENT_ID'] = 'foo-client'
    with pytest.raises(TypeError) as err:
        OAuth2Decorator(test_app)
    assert str(err.value) == 'OAUTH2_CLIENT_SECRET config property required'
