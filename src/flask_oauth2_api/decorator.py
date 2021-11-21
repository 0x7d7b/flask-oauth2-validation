from flask import Flask, request, make_response
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

    def __init__(self, status_code: int, error: str, error_message: str):
        self.status_code = status_code
        self.error = error
        self.error_message = error_message

    def response(self):
        response = make_response()
        response.headers.pop('Content-Type', None)
        response.status_code = self.status_code
        response.headers['WWW-Authenticate'] = ' '.join([
            'Bearer',
            'error="' + self.error + '"',
            self._error_description()
        ])
        return response

    def _error_description(self):
        return 'error_description="' + self.error_message + '"'


class OAuth2BadRequestException(OAuth2Exception):

    def __init__(self, error_message: str):
        super().__init__(400, 'invalid_request', error_message)


class OAuth2InvalidTokenException(OAuth2Exception):

    def __init__(self, error_message: str):
        super().__init__(401, 'invalid_token', error_message)


class OAuth2InsufficientScopeException(OAuth2Exception):

    def __init__(self, missing_scope: str):
        super().__init__(403, 'insufficient_scope', missing_scope)

    def _error_description(self):
        return 'scope="' + self.error_message + '"'


class OAuth2Decorator():
    """ Flask view function decorator which adds OAuth2 support.
    """

    def __init__(self, app: Flask):

        self._logger = logging.getLogger(__name__)

        app.config.setdefault('OAUTH2_ISSUER', None)
        app.config.setdefault('OAUTH2_AUDIENCE', None)
        app.config.setdefault('OAUTH2_JWKS_UPDATE_INTERVAL', None)
        app.config.setdefault('OAUTH2_CLIENT_ID', None)
        app.config.setdefault('OAUTH2_CLIENT_SECRET', None)

        # Holds the current requests token in case
        # the verification steps where all successful.
        self.token = None

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
            self._client_secret = app.config.get('OAUTH2_CLIENT_SECRET')
            if not self._client_secret:
                raise TypeError(
                    'OAUTH2_CLIENT_SECRET config property required'
                )

        # We are supposed to validate self encoded tokens
        # but don't have a pubkey and don't know the jwks_uri.
        # Then we need to retrieve it from the authorization
        # metadata endpoint
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

            # We need to look up the introspection endpoint from
            # the authorization server metadata.
            self._introspection_endpoint = self._lookup_metadata(
                'introspection_endpoint'
            )

            # Determine the auth method the introspection endpoint
            # supports (basic or post are implemented so far):
            server_supported_auth_methods = self._lookup_metadata(
                'introspection_endpoint_auth_methods_supported'
            )
            if 'client_secret_post' in server_supported_auth_methods:
                self._introspection_auth_method = 'client_secret_post'
            elif 'client_secret_basic' in server_supported_auth_methods:
                self._introspection_auth_method = 'client_secret_basic'
            else:
                raise TypeError(
                    'The introspection auth methods are not supported: ' +
                    ' '.join(server_supported_auth_methods)
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
                        str(response.status_code)
                    )
                metadata = response.json()
                self._cached_metadata = metadata
            else:
                metadata = self._cached_metadata
            if key in metadata:
                return metadata[key]
            raise TypeError(
                'No attribute ' +
                key +
                ' found in authorization server metadata'
            )
        except BaseException as http_error:
            raise TypeError(
                'Cannot request authorization server metadata: ' +
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
                    f'Cannot request public keys from {self._jwks_uri}: ' +
                    str(response.status_code)
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
                'Cannot request public keys from ' +
                self._jwks_uri +
                ': ' +
                str(http_error)
            )

    def _handle_token(self, fn, *args, **kwargs):
        """ OAuth2 decorator logic which is being executed
        whenever a decorated view function gets invoked.
        """
        introspect = kwargs['introspect']
        scopes = kwargs['scopes']
        decorated_exception = None
        try:
            if self._executor:
                self._executor.submit(self._update_keys)
            if not request.headers.get('Authorization', None):
                return OAuth2BadRequestException(
                    'Authorization header missing'
                ).response()
            token = self._extract_token(request.headers['Authorization'])
            if not token:
                return OAuth2BadRequestException(
                    'Bearer access token missing'
                ).response()
            if self._is_valid(token, introspect, scopes):
                kwargs.pop('scopes', None)
                kwargs.pop('introspect', None)
                try:
                    return fn(*args, **kwargs)
                except Exception as decorated_error:
                    decorated_exception = decorated_error
            else:
                return OAuth2InvalidTokenException(
                    'Invalid token'
                ).response()
        except OAuth2Exception as oauth2_exception:
            return oauth2_exception.response()
        except BaseException as error:
            self._logger.error(str(error))
            return OAuth2InvalidTokenException(
                'Token validation failed'
            ).response()
        if decorated_exception:
            raise decorated_exception

    def _extract_token(self, authorization_header: str):
        if not authorization_header.startswith('Bearer '):
            return None
        return authorization_header.split(sep=' ')[1]

    def _is_valid(self, token: str, introspect: bool, scopes: list) -> bool:
        if introspect and (not self._client_id or not self._client_secret):
            raise OAuth2InvalidTokenException('Invalid configuration')
        # First perform a local valiation
        valid = self._validate_jwt(token, scopes)
        if valid and introspect:
            # Then in case introspection is required perform a
            # remote validation in addition
            valid = valid and self._request_introspection(token)
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
                base64.b64encode(bytes(
                    self._client_id + ':' + self._client_secret,
                    encoding='utf-8'
                )).decode(encoding='utf-8')
        response = requests.post(
            url=self._introspection_endpoint,
            data=token_parameters,
            headers=token_headers
        )
        if not response.status_code == 200:
            self._logger.error(
                f'Unexpected introspection status code: {response.status_code}'
            )
            return False
        token_information = response.json()
        return 'active' in token_information \
            and token_information['active']

    def _validate_jwt(self, token: str, scopes: list) -> bool:
        pubkey = None
        if self._issuer_public_keys:
            key_id = self._lookup_key_id(token)
            if not key_id:
                raise OAuth2BadRequestException(
                    "No 'kid' attribute found in token header"
                )
            if key_id and key_id in self._issuer_public_keys:
                pubkey = jwk_from_dict(self._issuer_public_keys[key_id])
        if not pubkey:
            raise OAuth2InvalidTokenException(
                'Invalid token signature'
            )
        try:
            decoded = self._jwt.decode(
                token,
                pubkey,
                do_time_check=True
            )
            if 'iss' not in decoded or not self._issuer == decoded['iss']:
                raise OAuth2InvalidTokenException(
                    'Invalid token issuer'
                )
            if self._audience:
                if ('aud' not in decoded
                    or (type(self._audience) == dict
                        and decoded['aud'] not in self._audience)
                    or (type(self._audience) == str
                        and not self._audience == decoded['aud'])):
                    raise OAuth2InvalidTokenException(
                        'Invalid token audience'
                    )
            if scopes and 'scp' not in decoded:
                raise OAuth2InsufficientScopeException(
                    ' '.join(sorted(set(scopes)))
                )
            if scopes and 'scp' in decoded:
                decoded_scopes_set = set(decoded['scp'])
                if scopes and not set(scopes).issubset(decoded_scopes_set):
                    raise OAuth2InsufficientScopeException(
                        ' '.join(
                            sorted(set(scopes).difference(decoded_scopes_set))
                        )
                    )
            self.token = decoded
            return decoded
        except JWTDecodeError as decode_error:
            raise OAuth2InvalidTokenException(str(decode_error))

    def _lookup_key_id(self, token: str) -> str:
        try:
            header = token.split('.')[0]
            # Correct the padding
            header += '=' * (4 - len(header) % 4)
            jwt_header = json.loads(base64.b64decode(header).decode('utf-8'))
            if jwt_header and 'kid' in jwt_header:
                return jwt_header['kid']
        except BaseException:
            raise OAuth2BadRequestException('Invalid token format')

    def _update_keys(self):
        if (self._jwks_update_interval
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
                    *args,
                    **dict(
                        kwargs,
                        scopes=scopes,
                        introspect=introspect
                    )
                )
            return decorated
        return decorator