[![Python Package Build](https://github.com/0x7d7b/flask-oauth2-api/actions/workflows/python-build.yml/badge.svg)](https://github.com/0x7d7b/flask-oauth2-api/actions/workflows/python-build.yml)

This python package provides a Flask decorator which adds OAuth2 validation for self-encoded JWT based access tokens.

# Requirements
The authorization server has to support _Authorization Server Metadata_ (RFC-8414).

# Configuration
The minimal configuration expects the ```OAUTH2_ISSUER``` attribute being set only which points to the issuer:

    app.config['OAUTH2_ISSUER'] = 'https://<your-issuer>/oauth2'

This would perform local token validation after downloading the public keys from the authorization server.

In case you also need to perform remote token validation a ```OAUTH2_CLIENT_ID``` and ```OAUTH2_CLIENT_SECRET``` need to be configured:

    app.config['OAUTH2_CLIENT_ID'] = 'your-client-id'
    app.config['OAUTH2_CLIENT_SECRET'] = 'your-client-secret'

In case your authorization server uses rotating public keys an ```OAUTH2_JWKS_UPDATE_INTERVAL``` (in seconds) can be configured to regularly download the latest public keys from the authorization server:

    app.config['OAUTH2_JWKS_UPDATE_INTERVAL'] = 3600

For a more strict validation it is recommendet to configure an ```OAUTH2_AUDIENCE``` to verify the token against:

    app.config['OAUTH2_AUDIENCE'] = 'api://default'

# Usage
To provide OAuth2 token validation to your endpoints simply add the ```OAuth2Decorator```:

    from flask_oauth2_api import OAuth2Decoratory
    ...
    oauth2 = OAuth2Decorator(app)
    ...
    @oauth2.requires_token()
    @app.route('/protected')
    def protected():
        pass

This would perform local token validation, only. To enable remote token validation you need to provide the ```introspect=True``` argument:

    @oauth2.requires_token(introspect=True)
    @app.route('/protected')
    def protected():
        pass

In case you require one or multiple scopes to allow execution, add the ```scopes=[...]``` argument:

    @oauth2.requires_token(scopes=['profile', 'email'])
    @app.route('/protected')
    def protected():
        pass

To access the token from within your method you can access it via the ```OAuth2Decorator``` object like:

    @oauth2.requires_token()
    @app.route('/protected')
    def protected():
        token: dict = oauth2.token
        pass



# License

    MIT License

    Copyright (c) 2021 Henrik Sachse

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
