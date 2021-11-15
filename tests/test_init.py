from flask_oauth2_api import OAuth2Decorator
import pytest
from . import test_app, mocked_keys


def test_missing_config(test_app):
    """ At least the OAUTH2_ISSUER config attribute is required.
    This test is expected to raise a TypeError as no configuration
    attribute has been provided.
    """
    with pytest.raises(TypeError):
        app = test_app()
        OAuth2Decorator(app)


def test_issuer_only(test_app):
    """ Only the OAUTH2_ISSUER config attribute has been set.
    Thus we expect an authorization server metadata lookup to retrieve
    the jwks_uri. Next the jwks_uri should be requested to retrieve all
    public keys the authorization server uses.
    """
    app = test_app(meta_data=True, jwks_uri=True)
    app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    oauth2 = OAuth2Decorator(app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._jwks_uri == 'https://issuer.local/oauth2/keys'
    assert oauth2._issuer_public_keys == mocked_keys


def test_issuer_and_jwks_uri_configured(test_app):
    """ The OAUTH2_ISSUER and OAUTH2_JWKS_URIconfig attribute have been set.
    Thus we expect no authorization server metadata lookup to retrieve
    the jwks_uri. Only the jwks_uri should be requested to retrieve all
    public keys the authorization server uses.
    """
    app = test_app(jwks_uri=True)
    app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    app.config['OAUTH2_JWKS_URI'] = 'https://issuer.local/oauth2/keys'
    oauth2 = OAuth2Decorator(app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._jwks_uri == 'https://issuer.local/oauth2/keys'
    assert oauth2._issuer_public_keys == mocked_keys


def test_issuer_and_jwks_refresh_configured(test_app):
    """ The OAUTH2_ISSUER and OAUTH2_JWKS_URIconfig attribute have been set.
    Thus we expect no authorization server metadata lookup to retrieve
    the jwks_uri. Only the jwks_uri should be requested to retrieve all
    public keys the authorization server uses.
    """
    app = test_app(meta_data=True, jwks_uri=True)
    app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    app.config['OAUTH2_JWKS_URI'] = 'https://issuer.local/oauth2/keys'
    app.config['OAUTH2_JWKS_UPDATE_INTERVAL'] = 1234
    oauth2 = OAuth2Decorator(app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._jwks_uri == 'https://issuer.local/oauth2/keys'
    assert oauth2._issuer_public_keys == mocked_keys
    assert oauth2._jwks_update_interval == 1234
    assert oauth2._executor
    assert oauth2._jwks_last_update_timestamp


def test_introspection_setup(test_app):
    """ In case OAUTH2_CLIENT_ID and OAUTH2_CLIENT_SECRET
    attributes have been set we assume that we will
    validate tokens via introspection requests during
    runtime. Therefore we need to lookup the introspection
    endpoint from the authorization server metadata as well
    as the supported introspection endpoint auth methods.
    """
    # FIXME: 2 metadata request: introspect endpoint and auth methods
    app = test_app(meta_data=True)
    app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    app.config['OAUTH2_CLIENT_ID'] = 'foo-client'
    app.config['OAUTH2_CLIENT_SECRET'] = 'very-secure'
    oauth2 = OAuth2Decorator(app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._client_id == 'foo-client'
    assert oauth2._client_secret == 'very-secure'
    assert oauth2._introspection_endpoint == 'https://issuer.local/oauth2/introspect'
    assert oauth2._introspection_auth_method == 'client_secret_post'


def test_introspection_setup_without_secret(test_app):
    """ For using the introspection endpoint for validation
    we also need a client secret.
    """
    app = test_app(meta_data=True)
    app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    app.config['OAUTH2_CLIENT_ID'] = 'foo-client'
    with pytest.raises(TypeError):
        OAuth2Decorator(app)


def test_introspection_setup_with_endpoint(test_app):
    """ In case we specify an introspection endpoint
    we don't need to look it up from the metadata endpoint.
    But we need to look up the supported introspection auth
    methods from the metadata endpoint.
    """
    # FIXME: 1 metadata request to validate auth method
    app = test_app(meta_data=True)
    app.config['OAUTH2_ISSUER'] = 'https://issuer.local/oauth2'
    app.config['OAUTH2_CLIENT_ID'] = 'foo-client'
    app.config['OAUTH2_CLIENT_SECRET'] = 'very-secure'
    app.config['OAUTH2_OAUTH2_INTROSPECTION_ENDPOINT'] = 'https://issuer.local/oauth2/introspect'
    oauth2 = OAuth2Decorator(app)
    assert oauth2._issuer == 'https://issuer.local/oauth2'
    assert oauth2._client_id == 'foo-client'
    assert oauth2._client_secret == 'very-secure'
    assert oauth2._introspection_endpoint == 'https://issuer.local/oauth2/introspect'
    assert oauth2._introspection_auth_method == 'client_secret_post'
