#!/usr/bin/env python

from setuptools import setup

setup(
    name='servefile',
    description='Serve files from shell via a small HTTP server',
    long_description='Serve files from shell via a small HTTP server. The server redirects all HTTP requests to the file, so only IP and port must be given to another user to access the file. Its main purpose is to quickly send a file to users in your local network, independent of their current setup (OS/software). Beneath that it also supports uploads, SSL, HTTP basic auth and directory listings.',
    platforms='posix',
    version='0.4.4',
    license='GPLv3 or later',
    url='https://seba-geek.de/stuff/servefile/',
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
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Communications',
        'Topic :: Communications :: File Sharing',
        'Topic :: Internet',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Utilities',
    ],
)
