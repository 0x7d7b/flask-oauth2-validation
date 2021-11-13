from flask import request
from flask.app import Flask
from flask.json import jsonify
from functools import wraps
from jwt import JWT, jwk_from_dict
from jwt.exceptions import JWTDecodeError
import base64
import json
import logging
import requests


class OAuth2Exception(BaseException):
    def __init__(self, error_message: str):
        self.error = 'invalid_token'
        self.error_message = error_message


class OAuth2Decorator():

    def __init__(self, app: Flask):

        self._logger = logging.getLogger(__name__)

        app.config.setdefault('OAUTH2_ISSUER', None)
        app.config.setdefault('OAUTH2_JWKS_URI', None)
        app.config.setdefault('OAUTH2_CLIENT_ID', None)
        app.config.setdefault('OAUTH2_CLIENT_SECRET', None)
        app.config.setdefault('OAUTH2_INTROSPECTION_ENDPOINT', None)
        app.config.setdefault('OAUTH2_INTROSPECTION_AUTH_METHOD', None)

        # By default we assume that we validate JWT self-encoded tokens
        self._use_self_encoded_token = True

        self._issuer = None
        self._jwks_uri = None
        # FIXME: refresh keys regularly in case we have a valid jwks_uri!
        self._issuer_public_keys = None
        self._client_id = None
        self._client_secret = None
        self._introspection_endpoint = None
        self._introspection_auth_method = None
        self._jwks_uri = None
        self._jwt = None

        # The only mandatory value is the issuer URI.
        # In case it is the only value we expect it to offer
        # Authorization Server Metadata support (RFC-8414).
        if not app.config.get('OAUTH2_ISSUER'):
            raise TypeError('An OAUTH2_ISSUER config property is required')
        self._issuer = app.config.get('OAUTH2_ISSUER')

        # In case we have a client id we assume that we will use the
        # introspect endpoint and that we use reference tokens.
        self._client_id = app.config.get('OAUTH2_CLIENT_ID')
        if self._client_id:
            self._use_self_encoded_token = False
            self._client_secret = app.config.get('OAUTH2_CLIENT_SECRET')
            if not self._client_secret:
                raise TypeError(
                    'OAUTH2_CLIENT_SECRET config property required'
                )

        # We are supposed to validate self encoded tokens
        # but don't have a pubkey and don't know the jwks_uri.
        # Then we need to retrieve it from the authorization
        # metadata endpoint
        if (self._use_self_encoded_token
            and not self._issuer_pubkey
                and not self._jwks_uri):
            self._jwks_uri = self._lookup_metadata('jwks_uri')

        if self._use_self_encoded_token:
            # In case we don't have any public key we need to look
            # up all available pubkeys from the auth server
            if not self._issuer_pubkey:
                self._lookup_keys()
            self._jwt = JWT()
        else:
            # We use reference tokens and no self-encoded tokens
            self._introspection_endpoint = app.config.get(
                'OAUTH2_INTROSPECTION_ENDPOINT'
            )
            # When we don't have an introspection endpoint configured
            # we need to look it up from the metadata endpoint, first.
            if not self._introspection_endpoint:
                self._introspection_endpoint = self._lookup_metadata(
                    'introspection_endpoint'
                )
            self._introspection_auth_method = app.config.get(
                'OAUTH2_INTROSPECTION_AUTH_METHOD'
            )
            # By default we use the client_secret_post auth method
            if not self._introspection_auth_method:
                self._introspection_auth_method = 'client_secret_post'
            if (self._introspection_auth_method
                    not in ['client_secret_post', 'client_secret_basic']):
                raise TypeError(
                    'Unsupported introspection auth method:',
                    self._introspection_auth_method
                )
            # Once we've configure an auth method we need to
            # validate it against the ones supported by the server
            server_supported_auth_methods = self._lookup_metadata(
                'introspection_endpoint_auth_methods_supported'
            )
            if (self._introspection_auth_method
                    not in server_supported_auth_methods):
                raise TypeError(
                    'The configured introspection endpoint auth method',
                    'is not supported by the authorization server:',
                    self._introspection_auth_method
                )

    def _lookup_metadata(self, key: str) -> str:
        try:
            metadata_uri = self._issuer + \
                '/.well-known/oauth-authorization-server'
            self._logger.debug(
                'Trying to contact authorization server metadata endpoint at',
                metadata_uri,
            )
            response = requests.get(metadata_uri)
            if not response.status_code == 200:
                raise TypeError(
                    'Cannot request authorization server metadata',
                    response.status_code
                )
            metadata = response.json()
            if key in metadata:
                return metadata[key]
            raise TypeError(
                'No attribute',
                key,
                'found in authorization server metadata'
            )
        except BaseException as http_error:
            raise TypeError(
                'Cannot request authorization server metadata:',
                str(http_error)
            )

    def _lookup_keys(self) -> dict:
        try:
            self._logger.debug(
                'Trying to download public keys from authorization server at',
                self._jwks_uri
            )
            response = requests.get(self._jwks_uri)
            if not response.status_code == 200:
                raise TypeError(
                    'Cannot request public keys from',
                    self._jwks_uri,
                    response.status_code
                )
            jwks_metadata = response.json()
            if 'keys' in jwks_metadata:
                keys = jwks_metadata['keys']
                self._issuer_public_keys = {}
                for key in keys:
                    if 'kid' in key:
                        self._issuer_public_keys[key['kid']] = key
        except BaseException as http_error:
            raise TypeError(
                'Cannot request public keys from ',
                self._jwks_uri,
                ':',
                str(http_error)
            )

    def _handle_token(self, scopes: list, fn, *args, **kwds):
        try:
            if not request.headers.get('Authorization', None):
                return jsonify({
                    'error': 'invalid_token',
                    'error_description': 'Authorization header missing'
                }), 401
            token = self._extract_token(request.headers['Authorization'])
            if not token:
                return jsonify({
                    'error': 'invalid_token',
                    'error_description': 'Bearer access token missing'
                }), 401
            if self._is_valid(token):
                return fn(*args, **kwds)
            else:
                return jsonify({
                    'error': 'invalid_token',
                    'error_description': 'Invalid token'
                }), 401
        except OAuth2Exception as oauth2_exception:
            return jsonify({
                'error': oauth2_exception.error,
                'error_description': oauth2_exception.error_message
            }), 401
        except BaseException as error:
            self._logger.error(str(error))
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'Token validation failed'
            }), 401

    def _extract_token(self, authorization_header: str):
        if not authorization_header.startswith('Bearer '):
            return None
        return authorization_header.split(sep=' ')[1]

    def _is_valid(self, token: str) -> bool:
        if self._use_self_encoded_token:
            # We already either have a static configured pubkey or
            # we retrieved all possible pubkeys during init
            return self._validate_jwt(token)
        else:
            # We use reference tokens that means we need
            # to issue a request to the introspection endpoint
            return self._request_introspection(token)

    def _request_introspection(self, token: str) -> bool:
        token_parameters = {
            'token': token,
        }
        if self._introspection_auth_method == 'client_secret_post':
            token_parameters['client_id'] = self._client_id
            token_parameters['client_secret'] = self._client_secret
        token_headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        if self._introspection_auth_method == 'client_secret_basic':
            token_headers['Authentication'] = 'Basic ' + \
                base64.encode(self._client_id + ':' + self._client_secret)
        response = requests.post(
            url=self._introspection_endpoint,
            params=token_parameters,
            headers=token_headers
        )
        if not response.status_code == 200:
            self._logger.error(
                'Token introspection endpoint',
                'returned unexpected status code:',
                response.status_code
            )
            return None
        token_information = response.json()
        if 'active' in token_information and token_information['active']:
            return token_information
        return None

    def _validate_jwt(self, token: str) -> bool:
        pubkey = None
        if self._issuer_public_keys:
            key_id = self._lookup_key_id(token)
            if key_id and key_id in self._issuer_public_keys:
                pubkey = jwk_from_dict(self._issuer_public_keys[key_id])
        if not pubkey:
            raise OAuth2Exception(
                'Token signature invalid'
            )
        try:
            decoded = self._jwt.decode(
                token,
                pubkey,
                do_time_check=True
            )
            if 'iss' not in decoded or not self._issuer == decoded['iss']:
                raise OAuth2Exception('Invalid issuer')
            return decoded
        except JWTDecodeError as decode_error:
            raise OAuth2Exception(str(decode_error))

    def _lookup_key_id(self, token: str) -> str:
        try:
            header = token.split('.')[0]
            # Correct the padding
            header += '=' * (4 - len(header) % 4)
            jwt_header = json.loads(base64.b64decode(header).decode('utf-8'))
            if jwt_header and 'kid' in jwt_header:
                return jwt_header['kid']
        except BaseException:
            raise OAuth2Exception('Invalid token format')
        return None

    def requires_token(self, scopes=[]):
        def decorator(fn):
            @wraps(fn)
            def decorated(*args, **kwargs):
                return self._handle_token(scopes, fn, *args, **kwargs)
            return decorated
        return decorator
