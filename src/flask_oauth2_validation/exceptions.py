from flask import make_response


class OAuth2Exception(BaseException):
    """ Describes an HTTP error response which will be
    returned back to the client in case of any validation
    error.

    The method `OAuth2Exception.response()` constructs
    the Flask `flask.Response` object.

    Error responses have an empty body. A `WWW-Authenticate`
    response header will be set containing an error attribute
    specifying the actual type of error. Each individual
    `OAuth2Exception` subclass sets its own unique value.
    Additional attributes may also be set containing further
    error details.
    """

    def __init__(self, status_code: int, error: str, error_message: str):
        """ Creates an `OAuth2Exception` object.
        The `status_code` attributre defines the HTTP status code.
        The `error` attribute defines the unique type of error.
        And the `error_message` contains individual error details.
        """
        self.status_code = status_code
        self.error = error
        self.error_message = error_message

    def response(self):
        """ Assembles an `flask.Response` object including
        a `WWW-Authenticate` header.
        """

        response = make_response()

        # In case it has already been set we need to
        # drop the Content-Type header as the response
        # body will be empty.
        response.headers.pop('Content-Type', None)

        response.status_code = self.status_code
        response.headers['WWW-Authenticate'] = ' '.join([
            'Bearer',
            'error="' + self.error + '"',
            self._error_description()
        ])
        return response

    def _error_description(self):
        """ Creates a key-value pair to be added to the
        `WWW-Authenticate` header which contains individual
        error details.
        """
        return 'error_description="' + self.error_message + '"'


class OAuth2BadRequestException(OAuth2Exception):
    """ Describes an HTTP 400 (bad request) response:

        `WWW-Authenticate: Bearer error="invalid_request" \
                                  error_description="<msg>"`
    """

    def __init__(self, error_message: str):
        super().__init__(400, 'invalid_request', error_message)


class OAuth2InvalidTokenException(OAuth2Exception):
    """ Describes an HTTP 401 (unauthorized) response:

        `WWW-Authenticate: Bearer error="invalid_token" \
                                  error_description="<msg>"`
    """

    def __init__(self, error_message: str):
        super().__init__(401, 'invalid_token', error_message)


class OAuth2InsufficientScopeException(OAuth2Exception):
    """ Describes an HTTP 403 (forbidden) response. It contains
    a whitespace separated list of scopes required but not granted:

        `WWW-Authenticate: Bearer error="insufficient_scope" \
                                  scope="<scope1> <scope2> ... <scopeN>"`
    """

    def __init__(self, missing_scope: str):
        """ Creates an `OAuth2InsufficientScopeException` object.
        The `status_code` attributre defines the HTTP status code.
        The `error` attribute defines the unique type of error.
        And the `missing_scope` is a list containing required but
        not granted scopes.
        """
        super().__init__(403, 'insufficient_scope', missing_scope)

    def _error_description(self):
        return 'scope="' + self.error_message + '"'
