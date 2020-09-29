Servefile
=========

Serve files from shell via a small HTTP server. The server redirects all HTTP
requests to the file, so only IP and port must be given to another user to
access the file. Its main purpose is to quickly send a file to users in your
local network, independent of their current setup (OS/software). Besides that
it also supports uploads, SSL, HTTP basic auth and directory listings.

Features:
 * serve single file
 * serve a directory with directory index
 * file upload via webinterface
 * HTTPS with on the fly generated self signed SSL certificates
 * HTTP basic authentication
 * serving files/directories as on request generated tar files

Install
-------

Via pip
```shell
pip install servefile
```
After installation either execute `servefile --help` or `python -m servefile --help`

Standalone:
If you don't have pip available just copy `servefile/servefile.py` onto the target machine, make it executable and you are ready to go.
```shell
$ wget https://raw.githubusercontent.com/sebageek/servefile/master/servefile/servefile.py -O servefile
$ chmod +x servefile
$ ./servefile --help
```
