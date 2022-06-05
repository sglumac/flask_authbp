#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = []

test_requirements = []

setup(
    author="Slaven Glumac",
    author_email='slaven.glumac@gmail.com',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="Authentication and authorization blueprint for Flask applications.",
    install_requires=requirements,
    license="BSD license",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='flask_authbp',
    name='flask_authbp',
    packages=find_packages(include=['flask_authbp', 'flask_authbp.*']),
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/sglumac/flask_authbp',
    version='0.1.2',
    zip_safe=False,
)
