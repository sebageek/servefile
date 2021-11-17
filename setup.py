#!/usr/bin/env python

from setuptools import setup

with open("README.md") as f:
    long_description = f.read()

setup(
    name='servefile',
    description='Serve files from shell via a small HTTP server',
    long_description=long_description,
    long_description_content_type='text/markdown',
    platforms='posix',
    version='0.5.3',
    license='GPLv3 or later',
    url='https://github.com/sebageek/servefile/',
    author='Sebastian Lohff',
    author_email='seba@someserver.de',
    install_requires=['pyopenssl'],
    tests_require=[
        'pathlib2; python_version<"3"',
        'pytest',
        'requests',
    ],
    packages=["servefile"],
    entry_points={
        "console_scripts": [
            "servefile = servefile.servefile:main",
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Communications',
        'Topic :: Communications :: File Sharing',
        'Topic :: Internet',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Utilities',
    ],
)
