from flask import make_response


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
