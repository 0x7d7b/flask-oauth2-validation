from flask import Flask
from flask_oauth2_api import OAuth2Decorator
import pytest


def test_missing_config():
    with pytest.raises(TypeError):
        app = Flask(__name__)
        OAuth2Decorator(app)


def test_init():
    app = Flask(__name__)
    #oauth = OAuth2Decorator(app)
    # FIXME
