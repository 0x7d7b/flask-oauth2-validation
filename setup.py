from setuptools import setup

setup(
    name='flask-oauth2-api',
    packages=['flask-oauth2-api'],
    version='0.1.0',
    author='Henrik Sachse',
    author_email='0x7d7b@users.noreply.github.com',
    url='https://github.com/0x7d7b',
    license='BSD',
    description='Flask OAuth2 access token verification for resource servers',
    include_package_data=True,
    install_requires=[
        "jwt",
        "requests"
    ]
)
