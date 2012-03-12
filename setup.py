#!/usr/bin/python

from distutils.core import setup

setup(
	name='servefile',
	description='Script to serve files via a small HTTP server',
	long_description='Script to serve files via a small HTTP server. The server redirects all http requests to the file, so only IP and port must be given to another user to access the file.',
	platforms='posix',
	version='0.3',
	license='GPLv3 or later',
	url='http://seba-geek.de/stuff/servefile/',
	author='Sebastian Lohff',
	author_email='seba@someserver.de',
	scripts=['servefile'],
)

