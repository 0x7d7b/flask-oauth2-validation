from setuptools import find_packages, setup

# import src.flask_oauth2_api as flask_oauth2_api

setup_dependencies = [
    'flake8'
]

install_dependencies = [
    'jwt',
    'requests',
    'flask-executor',
    'flask'
]

test_dependencies = [
    'pytest',
    'pytest-cov',
    'coverage-lcov',
    'pytest-flask',
    'requests-mock'
]

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='flask-oauth2-api',
    version='0.1.0',
    author='Henrik Sachse',
    author_email='henrik@0x7d7b.net',
    description=(
        'Flask OAuth2 extension to verify self-encoded'
        'JWT based access tokens for resource servers'
    ),
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    url='https://github.com/0x7d7b/flask-oauth2-api',
    project_urls={
        'Bug Tracker': 'https://github.com/0x7d7b/flask-oauth2-api/issues',
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Framework :: Flask',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    package_dir={'': 'src'},
    packages=find_packages('src'),
    python_requires='>=3.6',
    include_package_data=True,
    setup_requires=setup_dependencies,
    install_requires=install_dependencies,
    test_suite='tests',
    tests_require=test_dependencies,
    extras_require={
        'test': test_dependencies
    }

)
