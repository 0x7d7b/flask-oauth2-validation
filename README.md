[![Build](https://github.com/0x7d7b/flask-oauth2-validation/actions/workflows/build.yml/badge.svg)](https://github.com/0x7d7b/flask-oauth2-validation/actions/workflows/build.yml) [![Test](https://github.com/0x7d7b/flask-oauth2-validation/actions/workflows/test.yml/badge.svg)](https://github.com/0x7d7b/flask-oauth2-validation/actions/workflows/test.yml) [![codecov](https://codecov.io/gh/0x7d7b/flask-oauth2-validation/branch/master/graph/badge.svg?token=JQ4K6QSMPT)](https://codecov.io/gh/0x7d7b/flask-oauth2-validation) [![License](https://img.shields.io/pypi/l/flask-oauth2-validation)](https://github.com/0x7d7b/flask-oauth2-validation/blob/master/LICENSE) [![mastodon](https://img.shields.io/mastodon/follow/109137478482490808?domain=https%3A%2F%2Fmastodon.social&style=social)](https://mastodon.social/@0x7d7b)

This Python package provides a [Flask](https://flask.palletsprojects.com/) decorator which adds local and remote _OAuth2_ ([RFC-6749](https://datatracker.ietf.org/doc/html/rfc6749)) validation for self-encoded _JWT_ ([RFC-7519](https://datatracker.ietf.org/doc/html/rfc7519)) based _Bearer_ ([RFC-6750](https://datatracker.ietf.org/doc/html/rfc6750)) access tokens.

It only covers validation logic required by _resource servers (APIs)_ and does not provide any implementation of OAuth2 flows (e.g. authorization code flow).

# Requirements
- The authorization server has to support _Authorization Server Metadata_ ([RFC-8414](https://datatracker.ietf.org/doc/html/rfc8414)).
- The JWT access tokens should follow the _JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens_ ([RFC-9068](https://www.rfc-editor.org/rfc/rfc9068.html)).

# Configuration
The minimal configuration expects the ```OAUTH2_ISSUER``` attribute being set which points to the issuer:

```python
app.config['OAUTH2_ISSUER'] = 'https://<your-issuer>/oauth2'
```

This would perform local token validation after downloading the public keys ([RFC-7517](https://datatracker.ietf.org/doc/html/rfc7517)) from the authorization server ([RFC-7800](https://datatracker.ietf.org/doc/html/rfc7800)).

In case you also need to perform remote token validation ([RFC-7662](https://datatracker.ietf.org/doc/html/rfc7662)) an ```OAUTH2_CLIENT_ID``` and ```OAUTH2_CLIENT_SECRET``` need to be configured:

```python
app.config['OAUTH2_CLIENT_ID'] = 'your-client-id'
app.config['OAUTH2_CLIENT_SECRET'] = 'your-client-secret'
```

In case your authorization server uses rotating public keys an ```OAUTH2_JWKS_UPDATE_INTERVAL``` (in seconds) could be configured to regularly download the latest public keys from the authorization server:

```python
app.config['OAUTH2_JWKS_UPDATE_INTERVAL'] = 3600
```

For a more strict validation it is recommended to configure an ```OAUTH2_AUDIENCE``` to verify the token against:

```python
app.config['OAUTH2_AUDIENCE'] = 'api://default'
```

# Usage
To provide OAuth2 token validation to your endpoints simply add the ```OAuth2Decorator```:

```python
from flask_oauth2_validation import OAuth2Decorator

oauth2 = OAuth2Decorator(app)

@oauth2.requires_token()
@app.route('/protected')
def protected():
    pass
```

This would perform local token validation, only. To enable remote token validation you need to provide the ```introspect=True``` argument:

```python
@oauth2.requires_token(introspect=True)
@app.route('/protected')
def protected():
    pass
```

In case you require one or multiple scopes to allow execution, add the ```scopes=[...]``` argument:

```python
@oauth2.requires_token(scopes=['profile', 'email'])
@app.route('/protected')
def protected():
    pass
```

To use the token from within your method you can access it via the ```OAuth2Decorator``` object like:

```python
@oauth2.requires_token()
@app.route('/protected')
def protected():
    token: dict = oauth2.token
    pass
```

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
