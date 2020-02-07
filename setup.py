#!/usr/bin/python

from distutils.core import setup

setup(
	name='servefile',
	description='Serve files from shell via a small HTTP server',
	long_description='Serve files from shell via a small HTTP server. The server redirects all HTTP requests to the file, so only IP and port must be given to another user to access the file. Its main purpose is to quickly send a file to users in your local network, independent of their current setup (OS/software). Beneath that it also supports uploads, SSL, HTTP basic auth and directory listings.',
	platforms='posix',
	version='0.4.4',
	license='GPLv3 or later',
	url='http://seba-geek.de/stuff/servefile/',
	author='Sebastian Lohff',
	author_email='seba@someserver.de',
	install_requires=['pyopenssl'],
	tests_require=[
		'pathlib2; python_version<"3"',
		'pytest',
		'requests',
	],
	scripts=['servefile'],
)

