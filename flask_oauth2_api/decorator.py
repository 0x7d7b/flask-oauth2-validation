from flask import Flask, jsonify, request
from flask_executor import Executor
from functools import wraps
from jwt import JWT, jwk_from_dict
from jwt.exceptions import JWTDecodeError
import base64
import json
import logging
import requests
import time
import threading


class OAuth2Exception(BaseException):
    """ Exception for building up an HTTP error response.
    In case an error occurs the OAuth2Exception attributes
    hold information which are being taken over into the
    json error response.
    """

    def __init__(self, error_message: str):
        self.error = 'invalid_token'
        self.error_message = error_message


class OAuth2Decorator():
    """ Flask view function decorator which adds OAuth2 support.
    """

    def __init__(self, app: Flask):

        self._logger = logging.getLogger(__name__)

        app.config.setdefault('OAUTH2_ISSUER', None)
        # FIXME: could be multiple audiences
        app.config.setdefault('OAUTH2_AUDIENCE', None)
        app.config.setdefault('OAUTH2_JWKS_URI', None)
        app.config.setdefault('OAUTH2_JWKS_UPDATE_INTERVAL', None)
        app.config.setdefault('OAUTH2_CLIENT_ID', None)
        app.config.setdefault('OAUTH2_CLIENT_SECRET', None)
        app.config.setdefault('OAUTH2_INTROSPECTION_ENDPOINT', None)
        app.config.setdefault('OAUTH2_INTROSPECTION_AUTH_METHOD', None)

        self._jwt = None
        self._issuer = None
        self._audience = None
        self._jwks_uri = None
        self._jwks_update_interval = None
        self._jwks_last_update_timestamp = None
        self._jwks_update_mutex = threading.Lock()
        self._executor = None
        self._issuer_public_keys = None
        self._client_id = None
        self._client_secret = None
        self._introspection_endpoint = None
        self._introspection_auth_method = None

        self._cached_metadata = None

        # The only mandatory value is the issuer URI.
        # In case it is the only value we expect it to offer
        # Authorization Server Metadata support (RFC-8414).
        if not app.config.get('OAUTH2_ISSUER'):
            raise TypeError('An OAUTH2_ISSUER config property is required')
        self._issuer = app.config.get('OAUTH2_ISSUER')

        # In case we have a client id we assume that we will use the
        # introspect endpoint.
        self._client_id = app.config.get('OAUTH2_CLIENT_ID')
        if self._client_id:
            self._use_self_encoded_token = False
            self._client_secret = app.config.get('OAUTH2_CLIENT_SECRET')
            if not self._client_secret:
                raise TypeError(
                    'OAUTH2_CLIENT_SECRET config property required'
                )

        # In case the authorization server does not support
        # metadata endpoints we can specify the JWKS URI manually.
        self._jwks_uri = app.config.get('OAUTH2_JWKS_URI')

        # We are supposed to validate self encoded tokens
        # but don't have a pubkey and don't know the jwks_uri.
        # Then we need to retrieve it from the authorization
        # metadata endpoint
        if not self._jwks_uri:
            self._jwks_uri = self._lookup_metadata('jwks_uri')

        # If an audience has been defined the JWT
        # token 'aud' attribute will be validated
        # against it
        self._audience = app.config.get('OAUTH2_AUDIENCE')

        # We're looking up the public keys from the
        # authorization server and specifying the
        # update interval to refresh the keys
        # regularly during runtime (if set)
        self._lookup_keys()
        self._jwks_last_update_timestamp = time.time()
        self._jwt = JWT()
        self._jwks_update_interval = app.config.get(
            'OAUTH2_JWKS_UPDATE_INTERVAL'
        )
        if self._jwks_update_interval:
            self._executor = Executor(app, 'oauth2_jwks_update_task')

        # In case we have a client_id and client_secret being set
        # we can use the introspection endpoint.
        if self._client_id and self._client_secret:

            # We can provide an introspection endpoint in case
            # the authorization server does not support metadata
            # requests.
            self._introspection_endpoint = app.config.get(
                'OAUTH2_INTROSPECTION_ENDPOINT'
            )

            # When we don't have an introspection endpoint configured
            # we need to look it up from the metadata endpoint.
            if not self._introspection_endpoint:
                self._introspection_endpoint = self._lookup_metadata(
                    'introspection_endpoint'
                )

            # It is possible to set up an introspection endpoint
            # auth method.
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

            # Once we've configured an auth method we need to
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
        """ Requests metadata information from an authorization endpoint
        according to RFC-8414.
        """
        try:
            if not self._cached_metadata:
                metadata_uri = self._issuer + \
                    '/.well-known/oauth-authorization-server'
                self._logger.debug(
                    f'Reading  metadata from {metadata_uri}',
                )
                response = requests.get(metadata_uri)
                if not response.status_code == 200:
                    raise TypeError(
                        'Cannot request authorization server metadata',
                        response.status_code
                    )
                metadata = response.json()
                self._cached_metadata = metadata
            else:
                metadata = self._cached_metadata
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
        """ Downloads the public keys from an authorization server.
        """
        try:
            self._logger.debug(
                f'Downloading public keys from {self._jwks_uri}'
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
                retrieved_keys = {}
                for key in keys:
                    if 'kid' in key:
                        retrieved_keys[key['kid']] = key
                self._issuer_public_keys = retrieved_keys
        except BaseException as http_error:
            raise TypeError(
                'Cannot request public keys from ',
                self._jwks_uri,
                ':',
                str(http_error)
            )

    def _handle_token(self, introspect: bool, scopes: list, fn, *args, **kwargs):
        """ OAuth2 decorator logic which is being executed
        whenever a decorated view function gets invoked.
        """
        try:
            if self._executor:
                self._executor.submit(self._update_keys)
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
            if self._is_valid(token, introspect, scopes):
                return fn(*args, **kwargs)
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

    def _is_valid(self, token: str, introspect: bool, scopes: list) -> bool:
        if introspect and (not self._client_id or not self._client_secret):
            raise OAuth2Exception('Invalid configuration')
        # First perform a local valiation
        valid = self._validate_jwt(token, scopes)
        if valid and introspect:
            # Then in case introspection is required perform a
            # remote validation in addition
            valid &= self._request_introspection(token)
        return valid

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
                f'Unexpected introspection status code: {response.status_code}'
            )
            return None
        token_information = response.json()
        if 'active' in token_information and token_information['active']:
            return token_information
        return None

    def _validate_jwt(self, token: str, scopes: list) -> bool:
        pubkey = None
        if self._issuer_public_keys:
            key_id = self._lookup_key_id(token)
            if key_id and key_id in self._issuer_public_keys:
                pubkey = jwk_from_dict(self._issuer_public_keys[key_id])
        if not pubkey:
            raise OAuth2Exception(
                'Invalid token signature'
            )
        try:
            decoded = self._jwt.decode(
                token,
                pubkey,
                do_time_check=True
            )
            if 'iss' not in decoded or not self._issuer == decoded['iss']:
                raise OAuth2Exception('Invalid token issuer')
            if self._audience:
                if ('aud' not in decoded
                        or not self._audience == decoded['aud']):
                    raise OAuth2Exception(
                        'Invalid token audience'
                    )
            if scopes and ('scp' not in decoded
                           or not set(scopes).issubset(decoded['scp'])):
                raise OAuth2Exception(
                    'Invalid scope'
                )
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

    def _update_keys(self):
        if (self._use_self_encoded_token
            and self._jwks_update_interval
                and self._jwks_last_update_timestamp):
            with self._jwks_update_mutex:
                now = time.time()
                if int(self._jwks_last_update_timestamp) + \
                        self._jwks_update_interval < now:
                    self._jwks_last_update_timestamp = now
                    try:
                        self._lookup_keys()
                    except TypeError as error:
                        self._logger.error(error)

    def requires_token(self, introspect=False, scopes=[]):
        """ Decorates a flask view function to add OAuth2 support.
        """
        def decorator(fn):
            @wraps(fn)
            def decorated(*args, **kwargs):
                return self._handle_token(
                    fn,
                    scopes=scopes,
                    introspect=introspect,
                    *args,
                    **kwargs
                )
            return decorated
        return decorator
