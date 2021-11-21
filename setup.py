from setuptools import find_packages, setup

install_dependencies = [
    'jwt',
    'requests',
    'flask-executor',
    'flask'
]

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='flask-oauth2-validation',
    version='0.1.0',
    author='Henrik Sachse',
    author_email='henrik@0x7d7b.net',
    description=(
        'A Flask decorator which adds local and remote OAuth2 '
        'validation for self-encoded JWT based Bearer access tokens.'
    ),
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    url='https://github.com/0x7d7b/flask-oauth2-validation',
    project_urls={
        'Bug Tracker': 'https://github.com/0x7d7b/flask-oauth2-validation/issues',
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
    install_requires=install_dependencies
)
