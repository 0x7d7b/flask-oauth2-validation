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
    assert oauth2._jwks_uri == 'https://issuer.local/oauth2/keys'
    assert oauth2._issuer_public_keys == mocked_keys
