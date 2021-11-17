#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Licensed under GNU General Public License v3 or later
# Written by Sebastian Lohff (seba@seba-geek.de)
# http://seba-geek.de/stuff/servefile/

from __future__ import print_function

__version__ = '0.5.3'

import argparse
import base64
import cgi
import datetime
import io
import mimetypes
import os
import re
import select
import socket
from subprocess import Popen, PIPE
import sys
import time

# fix imports for python2/python3
try:
    import BaseHTTPServer
    import SocketServer
    from urllib import quote, unquote
except ImportError:
    # both have different names in python3
    import http.server as BaseHTTPServer
    import socketserver as SocketServer
    from urllib.parse import quote, unquote

# only activate SSL if available
HAVE_SSL = False
try:
	from OpenSSL import SSL, crypto
	HAVE_SSL = True
except ImportError:
	pass

def getDateStrNow():
	""" Get the current time formatted for HTTP header """
	now = datetime.datetime.fromtimestamp(time.mktime(time.gmtime()))
	return now.strftime("%a, %d %b %Y %H:%M:%S GMT")

class FileBaseHandler(BaseHTTPServer.BaseHTTPRequestHandler):
	fileName = None
	blockSize = 1024 * 1024
	server_version = "servefile/" + __version__

	def checkAndDoRedirect(self, fileName=None):
		""" If request didn't request self.fileName redirect to self.fileName.

		Returns True if a redirect was issued. """
		if not fileName:
			fileName = self.fileName
		if unquote(self.path) != "/" + fileName:
			self.send_response(302)
			self.send_header('Location', '/' + quote(fileName))
			self.end_headers()
			return True
		return False

	def sendContentHeaders(self, fileName, fileLength, lastModified=None):
		""" Send default Content headers for given fileName and fileLength.

		If no lastModified is given the current date is taken. If
		fileLength is lesser than 0 no Content-Length will be sent."""
		if not lastModified:
			lastModified = getDateStrNow()

		if fileLength >= 0:
			self.send_header('Content-Length', str(fileLength))
		self.send_header('Connection', 'close')
		self.send_header('Last-Modified', lastModified)
		self.send_header('Content-Type', 'application/octet-stream')
		self.send_header('Content-Disposition', 'attachment; filename="%s"' % fileName)
		self.send_header('Content-Transfer-Encoding', 'binary')

	def isRangeRequest(self):
		""" Return True if partial content is requestet """
		return "Range" in self.headers

	def handleRangeRequest(self, fileLength):
		""" Find out and handle continuing downloads.

		Returns a tuple of a boolean, if this is a valid range request,
		and a range. When the requested range is out of range, range is
		set to None.
		"""
		fromto = None
		if self.isRangeRequest():
			cont = self.headers.get("Range").split("=")
			if len(cont) > 1 and cont[0] == 'bytes':
				fromto = cont[1].split('-')
				if len(fromto) > 1:
					if fromto[1] == '':
						fromto[1] = fileLength - 1
					try:
						fromto[0] = int(fromto[0])
						fromto[1] = int(fromto[1])
					except ValueError:
						return (False, None)

					if fromto[0] >= fileLength or fromto[0] < 0 or fromto[1] >= fileLength or fromto[1]-fromto[0] < 0:
						# oops, already done! (requested range out of range)
						self.send_response(416)
						self.send_header('Content-Range', 'bytes */%d' % fileLength)
						self.end_headers()
						return (True, None)
					return (True, fromto)
		# broken request or no range header
		return (False, None)

	def sendFile(self, filePath, fileLength=None, lastModified=None):
		""" Send file with continuation support.

		filePath: path to file to be sent
		fileLength: length of file (if None is given this will be found out)
		lastModified: time the file was last modified, None for "now"
		"""
		if not fileLength:
			fileLength = os.stat(filePath).st_size

		(responseCode, myfile) = self.getFileHandle(filePath)
		if not myfile:
			self.send_response(responseCode)
			self.end_headers()
			return

		(continueDownload, fromto) = self.handleRangeRequest(fileLength)
		if continueDownload:
			if not fromto:
				# we are done
				return True

			# now we can wind the file *brrrrrr*
			myfile.seek(fromto[0])

		if fromto != None:
			self.send_response(216)
			self.send_header('Content-Range', 'bytes %d-%d/%d' % (fromto[0], fromto[1], fileLength))
			fileLength = fromto[1] - fromto[0] + 1
		else:
			self.send_response(200)

		fileName = self.fileName
		if not fileName:
			fileName = os.path.basename(filePath)
		self.sendContentHeaders(fileName, fileLength, lastModified)
		self.end_headers()
		block = self.getChunk(myfile, fromto)
		while block:
			self.wfile.write(block)
			block = self.getChunk(myfile, fromto)
		myfile.close()
		print("%s finished downloading %s" % (self.client_address[0], filePath))
		return True

	def getChunk(self, myfile, fromto):
		if fromto and myfile.tell()+self.blockSize >= fromto[1]:
			readsize = fromto[1]-myfile.tell()+1
		else:
			readsize = self.blockSize
		return myfile.read(readsize)

	def getFileHandle(self, path):
		""" Get handle to a file.

		Return a tuple of HTTP response code and file handle.
		If the handle couldn't be acquired it is set to None
		and an appropriate HTTP error code is returned.
		"""
		myfile = None
		responseCode = 200
		try:
			myfile = open(path, 'rb')
		except IOError as e:
			responseCode = self.getResponseForErrno(e.errno)
		return (responseCode, myfile)

	def getFileLength(self, path):
		""" Get length of a file.

		Return a tuple of HTTP response code and file length.
		If filelength couldn't be determined, it is set to -1
		and an appropriate HTTP error code is returned.
		"""
		fileSize = -1
		responseCode = 200
		try:
			fileSize = os.stat(path).st_size
		except IOError as e:
			responseCode = self.getResponseForErrno(e.errno)
		return (responseCode, fileSize)

	def getResponseForErrno(self, errno):
		""" Return HTTP response code for an IOError errno """
		if errno == errno.ENOENT:
			return 404
		elif errno == errno.EACCESS:
			return 403
		else:
			return 500


class FileHandler(FileBaseHandler):
	filePath = "/dev/null"
	fileLength = 0
	startTime = getDateStrNow()

	def do_HEAD(self):
		if self.checkAndDoRedirect():
			return
		self.send_response(200)
		self.sendContentHeaders(self.fileName, self.fileLength, self.startTime)
		self.end_headers()

	def do_GET(self):
		if self.checkAndDoRedirect():
			return
		self.sendFile(self.filePath, self.fileLength, self.startTime)


class TarFileHandler(FileBaseHandler):
	target = None
	compression = "none"
	compressionMethods = ("none", "gzip", "bzip2", "xz")

	def do_HEAD(self):
		if self.checkAndDoRedirect():
			return
		self.send_response(200)
		self.sendContentHeaders(self.fileName, -1)
		self.end_headers()

	def do_GET(self):
		if self.checkAndDoRedirect():
			return

		tarCmd = Popen(self.getCompressionCmd(), stdout=PIPE)
		# give the process a short time to find out if it can
		# pack/compress the file
		time.sleep(0.05)
		if tarCmd.poll() != None and tarCmd.poll() != 0:
			# something went wrong
			print("Error while compressing '%s'. Aborting request." % self.target)
			self.send_response(500)
			self.end_headers()
			return

		self.send_response(200)
		self.sendContentHeaders(self.fileName, -1)
		self.end_headers()

		block = True
		while block and block != '':
			block = tarCmd.stdout.read(self.blockSize)
			if block and block != '':
				self.wfile.write(block)
		print("%s finished downloading" % (self.client_address[0]))

	def getCompressionCmd(self):
		if self.compression == "none":
			cmd = ["tar", "-c"]
		elif self.compression == "gzip":
			cmd = ["tar", "-cz"]
		elif self.compression == "bzip2":
			cmd = ["tar", "-cj"]
		elif self.compression == "xz":
			cmd = ["tar", "-cJ"]
		else:
			raise ValueError("Unknown compression mode '%s'." % self.compression)

		dirname = os.path.basename(self.target.rstrip("/"))
		chdirTo = os.path.dirname(self.target.rstrip("/"))
		if chdirTo != '':
			cmd.extend(["-C", chdirTo])
		cmd.append(dirname)
		return cmd

	@staticmethod
	def getCompressionExt():
		if TarFileHandler.compression == "none":
			return ".tar"
		elif TarFileHandler.compression == "gzip":
			return ".tar.gz"
		elif TarFileHandler.compression == "bzip2":
			return ".tar.bz2"
		elif TarFileHandler.compression == "xz":
			return ".tar.xz"
		raise ValueError("Unknown compression mode '%s'." % TarFileHandler.compression)


class DirListingHandler(FileBaseHandler):
	""" DOCUMENTATION MISSING """

	targetDir = None

	def do_HEAD(self):
		self.getFileOrDirectory(head=True)

	def do_GET(self):
		self.getFileOrDirectory(head=False)

	def getFileOrDirectory(self, head=False):
		""" Send file or directory index, depending on requested path """
		path = self.getCleanPath()

		# check if path is in current serving directory
		currBaseDir = self.targetDir + os.path.sep
		requestPath = os.path.normpath(os.path.join(currBaseDir, path)) + os.path.sep
		if not requestPath.startswith(currBaseDir):
			self.send_response(301)
			self.send_header("Location", '/')
			self.end_headers()
			return

		if os.path.isdir(path):
			if not self.path.endswith('/'):
				self.send_response(301)
				self.send_header("Location", self.path + '/')
				self.end_headers()
			else:
				self.sendDirectoryListing(path, head)
		elif os.path.isfile(path):
			if head:
				(response, length) = self.getFileLength(path)
				if length < 0:
					self.send_response(response)
					self.end_headers()
				else:
					self.send_response(200)
					self.sendContentHeaders(path, length)
					self.end_headers()
			else:
				self.sendFile(path, head)
		else:
			self.send_response(404)
			errorMsg = """<!DOCTYPE html><html>
				<head><title>404 Not Found</title></head>
				<body>
				<h1>Not Found</h1>
				<p>The requestet URL %s was not found on this server</p>
				<p><a href="/">Back to /</a>
				</body>
				</html>""" % self.escapeHTML(unquote(self.path))
			self.send_header("Content-Length", str(len(errorMsg)))
			self.send_header('Connection', 'close')
			self.end_headers()
			if not head:
				self.wfile.write(errorMsg.encode())

	def escapeHTML(self, htmlstr):
		entities = [("<", "&lt;"), (">", "&gt;")]
		for src, dst in entities:
			htmlstr = htmlstr.replace(src, dst)
		return htmlstr

	def _appendToListing(self, content, item, itemPath, stat, is_dir):
		# Strings to display on directory listing
		lastModifiedDate = datetime.datetime.fromtimestamp(stat.st_mtime)
		lastModified = lastModifiedDate.strftime("%Y-%m-%d %H:%M")
		fileSize = "%.1f%s" % self.convertSize(stat.st_size)
		(fileType, _) = mimetypes.guess_type(itemPath)
		if not fileType:
			fileType = "-"

		if is_dir:
			item += "/"
			fileType = "Directory"
		content.append("""
			<tr>
				<td class="name"><a href="%s">%s</a></td>
				<td class="last-modified">%s</td>
				<td class="size">%s</td>
				<td class="type">%s</td>
			</tr>
		""" % (quote(item), item, lastModified, fileSize, fileType))

	def sendDirectoryListing(self, path, head):
		""" Generate a directorylisting for path and send it """
		header = """<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<title>Index of %(path)s</title>
		<style type="text/css">
			a { text-decoration: none; color: #0000BB;}
			a:visited { color: #000066;}
			a:hover, a:focus, a:active { text-decoration: underline; color: #cc0000; text-indent: 5px; }
			body { background-color: #eaeaea; padding: 20px 0; margin: 0; font: 400 13px/1.2em Arial, sans-serif; }
			h1 { margin: 0 10px 12px 10px; font-family: Arial, sans-serif; }
			div.content { background-color: white; border-color: #ccc; border-width: 1px 0; border-style: solid; padding: 10px 10px 15px 10px; }
			td { padding-right: 15px; text-align: left; font-family: monospace; }
			th { font-weight: bold; font-size: 115%%; padding: 0 15px 5px 0; text-align: left; }
			.size { text-align: right; }
			.footer { font: 12px monospace; color: #333; margin: 5px 10px 0; }
			.footer, h1 { text-shadow: 0 1px 0 white; }
		</style>
	</head>
<body>
	<h1>Index of %(path)s</h1>
	<div class="content">
	<table summary="Directory Listing">
		<thead>
			<tr>
				<th class="name"><a onclick="sort('name');">Name</a></th>
				<th class="last-modified"><a onclick="sort('last-modified');">Last Modified</a></th>
				<th class="size"><a onclick="sort('size');">Size</a></th>
				<th class="type">Type</th>
			</tr>
		</thead>
		<tbody>
		""" % {'path': os.path.normpath(unquote(self.path))}
		footer = """</tbody></table></div>
<div class="footer"><a href="http://seba-geek.de/stuff/servefile/">servefile %(version)s</a></div>
<script>
    function unhumanize(text){
        var powers = {'K': 1, 'M': 2, 'G': 3, 'T': 4};
        var number = parseFloat(text.slice(0, text.length - 1));
        var unit = text.slice(text.length - 1);
        return number * Math.pow(1024, powers[unit]);
    }


    function compare_class(cls, modifier, a, b){
        var atext = a.getElementsByClassName(cls).item(0).textContent,
            btext = b.getElementsByClassName(cls).item(0).textContent,
            atype = a.getElementsByClassName("type").item(0).innerHTML,
            btype = b.getElementsByClassName("type").item(0).innerHTML;

        // always keep directories on top
        if (atype !== btype) {
            if (atype === "Directory")
                return -1
            if (btype === "Directory")
                return 1
        }

        if (cls === "name"){
            if (atype === "Directory")
                atext = atext.slice(0, atext.length - 1);

            if (btype === "Directory")
                btext = btext.slice(0, btext.length - 1);
        }

        if (cls === "size"){
            aint = unhumanize(atext);
            bint = unhumanize(btext);
            // don't change the order of same-size objects
            if (aint === bint)
                return 1;
            return aint > bint ? modifier : -modifier;
        }
        else
            return atext.localeCompare(btext) * modifier;
    }


    function move_rows(e, i, a){
        if (i === a.length - 1)
            return;
        var par = e.parentNode,
            next = e.nextSibling;
        if (next === a[i+1])
            return;
        par.removeChild(a[i+1]);
        if (next)
            par.insertBefore(a[i+1], next);
        else
            par.appendChild(a[i+1]);
    }

    function sort(cls){
        var arr = Array.prototype.slice.call(document.getElementsByTagName("tr"));
        var e = arr.shift();
        if (!e.sort_modifier || e.sort_cls !== cls)
            if (cls === "name")
                e.sort_modifier = -1;
            else
                e.sort_modifier = 1;
        e.sort_cls = cls;
        e.sort_modifier = -1 * e.sort_modifier;
        arr = arr.sort(function (a, b) { return compare_class(cls, e.sort_modifier, a, b); });
        arr.forEach(move_rows);
    }

    var e = document.getElementsByTagName("tr").item(0);
    e.sort_modifier = 1;
    e.sort_cls = "name";
</script>
</body>
</html>""" % {'version': __version__}
		content = []

		dir_items = list()
		file_items = list()

		for item in [".."] + sorted(os.listdir(path), key=lambda x:x.lower()):
				# create path to item
				itemPath = os.path.join(path, item)

				# Hide "../" in listing of the (virtual) root directory
				if item == '..' and path == DirListingHandler.targetDir.rstrip('/') + '/':
					continue

				# try to stat file for size, last modified... continue on error
				stat = None
				try:
					stat = os.stat(itemPath)
				except IOError:
					continue

				if os.path.isdir(itemPath):
					target_items = dir_items
				else:
					target_items = file_items
				target_items.append((item, itemPath, stat))

		# Directories first, then files
		for (tuple_list, is_dir) in (
				(dir_items, True),
				(file_items, False),
				):
			for (item, itemPath, stat) in tuple_list:
				self._appendToListing(content, item, itemPath, stat, is_dir=is_dir)

		listing = header + "\n".join(content) + footer

		# write listing
		self.send_response(200)
		self.send_header("Content-Type", "text/html")
		if head:
			self.end_headers()
			return
		self.send_header("Content-Length", str(len(listing)))
		self.send_header('Connection', 'close')
		self.end_headers()
		if sys.version_info.major >= 3:
			listing = listing.encode()
		self.wfile.write(listing)

	def convertSize(self, size):
		for ext in "KMGT":
			size /= 1024.0
			if size < 1024.0:
				break
		if ext == "K" and size < 0.1:
			size = 0.1
		return (size, ext.strip())

	def getCleanPath(self):
		urlPath = os.path.normpath(unquote(self.path)).strip("/")
		path = os.path.join(self.targetDir, urlPath)
		return path


class FilePutter(BaseHTTPServer.BaseHTTPRequestHandler):
	""" Simple HTTP Server which allows uploading to a specified directory
	either via multipart/form-data or POST/PUT requests containing the file.
	"""

	targetDir = None
	maxUploadSize = 0
	blockSize = 1024 * 1024
	uploadPage = """
<!docype html>
<html>
	<form action="/" method="post" enctype="multipart/form-data">
		<label for="file">Filename:</label>
		<input type="file" name="file" id="file" />
		<br />
		<input type="submit" name="submit" value="Upload" />
	</form>
</html>
"""

	def do_GET(self):
		""" Answer every GET request with the upload form """
		self.sendResponse(200, self.uploadPage)

	def do_POST(self):
		""" Upload a file via POST

		If the content-type is multipart/form-data it checks for the file
		field and saves the data to disk. For other content-types it just
		calls do_PUT and is handled as such except for the http response code.

		Files can be uploaded with wget --post-file=path/to/file <url> or
		curl -X POST -d @file <url> .
		"""
		length = self.getContentLength()
		if length < 0:
			return
		print(self.headers)
		ctype = self.headers.get('Content-Type')

		# check for multipart/form-data.
		if not (ctype and ctype.lower().startswith("multipart/form-data")):
			# not a normal multipart request ==> handle as PUT request
			return self.do_PUT(fromPost=True)

		# create FieldStorage object for multipart parsing
		env = os.environ
		env['REQUEST_METHOD'] = "POST"
		fstorage = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=env)
		if not "file" in fstorage:
			self.sendResponse(400, "No file found in request.")
			return

		destFileName = self.getTargetName(fstorage["file"].filename)
		if destFileName == "":
			self.sendResponse(400, "Filename was empty or invalid")
			return

		# write file down to disk, send a 200 afterwards
		target = open(destFileName, "wb")
		bytesLeft = length
		while bytesLeft > 0:
			bytesToRead = min(self.blockSize, bytesLeft)
			target.write(fstorage["file"].file.read(bytesToRead))
			bytesLeft -= bytesToRead
		target.close()
		self.sendResponse(200, "OK! Thanks for uploading")
		print("Received file '%s' from %s." % (destFileName, self.client_address[0]))

	def do_PUT(self, fromPost=False):
		""" Upload a file via PUT

		The request path is used as filename, so uploading a file to the url
		http://host:8080/testfile will cause the file to be named testfile. If
		no filename is given, a random name will be generated.

		Files can be uploaded with e.g. curl -T file <url> .
		"""
		length = self.getContentLength()
		if length < 0:
			return

		fileName = unquote(self.path)
		if fileName == "/":
			# if no filename was given we have to generate one
			fileName = str(time.time())

		cleanFileName = self.getTargetName(fileName)
		if cleanFileName == "":
			self.sendResponse(400, "Filename was invalid")
			return

		# Sometimes clients want to be told to continue with their transfer
		if self.headers.get("Expect") == "100-continue":
			self.send_response(100)
			self.end_headers()

		target = open(cleanFileName, "wb")
		bytesLeft = int(self.headers['Content-Length'])
		while bytesLeft > 0:
			bytesToRead = min(self.blockSize, bytesLeft)
			target.write(self.rfile.read(bytesToRead))
			bytesLeft -= bytesToRead
		target.close()
		self.sendResponse(200 if fromPost else 201, "OK!")

	def getContentLength(self):
		length = 0
		try:
			length = int(self.headers['Content-Length'])
		except (ValueError, KeyError):
			pass
		if length <= 0:
			self.sendResponse(411, "Content-Length was invalid or not set.")
			return -1
		if self.maxUploadSize > 0 and length > self.maxUploadSize:
			self.sendResponse(413, "Your file was too big! Maximum allowed size is %d byte. <a href=\"/\">back</a>" % self.maxUploadSize)
			return -1
		return length

	def sendResponse(self, code, msg):
		""" Send a HTTP response with HTTP statuscode code and message msg,
		providing the correct content-length.
		"""
		self.send_response(code)
		self.send_header('Content-Type', 'text/html')
		self.send_header('Content-Length', str(len(msg)))
		self.send_header('Connection', 'close')
		self.end_headers()
		self.wfile.write(msg.encode())

	def getTargetName(self, fname):
		""" Generate a clean and secure filename.

		This function takes a filename and strips all the slashes out of it.
		If the file already exists in the target directory, a (NUM) will be
		appended, so no file will be overwritten.
		"""
		cleanFileName = fname.replace("/", "")
		if cleanFileName == "":
			return ""
		destFileName = os.path.join(self.targetDir, cleanFileName)
		if not os.path.exists(destFileName):
			return destFileName
		else:
			i = 1
			extraDestFileName = destFileName + "(%s)" % i
			while os.path.exists(extraDestFileName):
				i += 1
				extraDestFileName = destFileName + "(%s)" % i
			return extraDestFileName
		# never reached

class ThreadedHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
	def handle_error(self, request, client_address):
		_, exc_value, _ = sys.exc_info()
		print("%s ABORTED transmission (Reason: %s)" % (client_address[0], exc_value))


def catchSSLErrors(BaseSSLClass):
	""" Class decorator which catches SSL errors and prints them. """
	class X(BaseSSLClass):
		def handle_one_request(self, *args, **kwargs):
			try:
				BaseSSLClass.handle_one_request(self, *args, **kwargs)
			except SSL.Error as e:
				if str(e) == "":
					print("%s SSL error (empty error message)" % (self.client_address[0],))
				else:
					print("%s SSL error: %s" % (self.client_address[0], e))
	return X


class SecureThreadedHTTPServer(ThreadedHTTPServer):
	def __init__(self, pubKey, privKey, server_address, RequestHandlerClass, bind_and_activate=True):
		ThreadedHTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

		# choose TLS1.2 or TLS1, if available
		sslMethod = None
		if hasattr(SSL, "TLSv1_2_METHOD"):
			sslMethod = SSL.TLSv1_2_METHOD
		elif hasattr(SSL, "TLSv1_METHOD"):
			sslMethod = SSL.TLSv1_METHOD
		else:
			# only SSLv23 available
			print("Warning: Only SSLv2/SSLv3 is available, connection might be insecure.")
			sslMethod = SSL.SSLv23_METHOD

		ctx = SSL.Context(sslMethod)
		if type(pubKey) is crypto.X509 and type(privKey) is crypto.PKey:
			ctx.use_certificate(pubKey)
			ctx.use_privatekey(privKey)
		else:
			ctx.use_certificate_file(pubKey)
			ctx.use_privatekey_file(privKey)

		self.bsocket = socket.socket(self.address_family, self.socket_type)
		self.socket = SSL.Connection(ctx, self.bsocket)

		if bind_and_activate:
			self.server_bind()
			self.server_activate()

	def shutdown_request(self, request):
		try:
			request.shutdown()
		except SSL.Error:
			# ignore SSL errors on connection shutdown
			pass


class SecureHandler():
	def setup(self):
		self.connection = self.request

		if sys.version_info[0] > 2:
			# python3 SocketIO (replacement for socket._fileobject)
			raw_read_sock = socket.SocketIO(self.request, 'rb')
			raw_write_sock = socket.SocketIO(self.request, 'wb')
			rbufsize = self.rbufsize > 0 and self.rbufsize or io.DEFAULT_BUFFER_SIZE
			wbufsize = self.wbufsize > 0 and self.wbufsize or io.DEFAULT_BUFFER_SIZE
			self.rfile = io.BufferedReader(raw_read_sock, rbufsize)
			self.wfile = io.BufferedWriter(raw_write_sock, wbufsize)
		else:
			# python2 does not have SocketIO
			self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
			self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

class ServeFileException(Exception):
	pass


class ServeFile():
	""" Main class to manage everything. """

	_NUM_MODES = 4
	(MODE_SINGLE, MODE_SINGLETAR, MODE_UPLOAD, MODE_LISTDIR) = range(_NUM_MODES)

	def __init__(self, target, port=8080, serveMode=0, useSSL=False):
		self.target = target
		self.port = port
		self.serveMode = serveMode
		self.dirCreated = False
		self.useSSL = useSSL
		self.cert = self.key = None
		self.auth = None
		self.maxUploadSize = 0
		self.listenIPv4 = True
		self.listenIPv6 = True

		if self.serveMode not in range(self._NUM_MODES):
			self.serveMode = None
			raise ValueError("Unknown serve mode, needs to be MODE_SINGLE, MODE_SINGLETAR, MODE_UPLOAD or MODE_DIRLIST.")

	def setIPv4(self, ipv4):
		""" En- or disable ipv4 """
		self.listenIPv4 = ipv4

	def setIPv6(self, ipv6):
		""" En- or disable ipv6 """
		self.listenIPv6 = ipv6

	def getIPs(self):
		""" Get IPs from all interfaces via ip or ifconfig. """
		# ip and ifconfig sometimes are located in /sbin/
		os.environ['PATH'] += ':/sbin:/usr/sbin'
		proc = Popen(r"ip addr|" + \
					  "sed -n -e 's/.*inet6\{0,1\} \([0-9.a-fA-F:]\+\).*/\\1/ p'|" + \
					  "grep -v '^fe80\|^127.0.0.1\|^::1'", \
					  shell=True, stdout=PIPE, stderr=PIPE)
		if proc.wait() != 0:
			# ip failed somehow, falling back to ifconfig
			oldLang = os.environ.get("LC_ALL", None)
			os.environ['LC_ALL'] = "C"
			proc = Popen(r"ifconfig|" + \
						  "sed -n 's/.*inet6\{0,1\}\( addr:\)\{0,1\} \{0,1\}\([0-9a-fA-F.:]*\).*/" + \
						  "\\2/p'|" + \
						  "grep -v '^fe80\|^127.0.0.1\|^::1'", \
						  shell=True, stdout=PIPE, stderr=PIPE)
			if oldLang:
				os.environ['LC_ALL'] = oldLang
			else:
				del(os.environ['LC_ALL'])
			if proc.wait() != 0:
				# we couldn't find any ip address
				proc = None
		if proc:
			ips = proc.stdout.read().decode().strip().split("\n")

			# filter out ips we are not listening on
			if not self.listenIPv6:
				ips = [ip for ip in ips if '.' in ip]
			if not self.listenIPv4:
				ips = [ip for ip in ips if ':' in ip]

			return ips
		return None

	def setSSLKeys(self, cert, key):
		""" Set SSL cert/key. Can be either path to file or pyopenssl X509/PKey object. """
		self.cert = cert
		self.key = key

	def setMaxUploadSize(self, limit):
		""" Set the maximum upload size in byte """
		self.maxUploadSize = limit

	def setCompression(self, compression):
		""" Set the compression of TarFileHandler """
		if self.serveMode != self.MODE_SINGLETAR:
			raise ServeFileException("Compression mode can only be set in tar-mode.")
		if compression not in TarFileHandler.compressionMethods:
			raise ServeFileException("Compression mode not available.")
		TarFileHandler.compression = compression

	def genKeyPair(self):
		print("Generating SSL certificate...", end="")
		sys.stdout.flush()

		pkey = crypto.PKey()
		pkey.generate_key(crypto.TYPE_RSA, 2048)

		req = crypto.X509Req()
		subj = req.get_subject()
		subj.CN = "127.0.0.1"
		subj.O = "servefile laboratories"
		subj.OU = "servefile"

		# generate altnames
		altNames = []
		for ip in self.getIPs() + ["127.0.0.1", "::1"]:
			altNames.append("IP:%s" % ip)
		altNames.append("DNS:localhost")
		ext = crypto.X509Extension(b"subjectAltName", False, (",".join(altNames)).encode())
		req.add_extensions([ext])

		req.set_pubkey(pkey)
		req.sign(pkey, "sha1")

		cert = crypto.X509()
		# Mozilla only accepts v3 certificates with v3 extensions, not v1
		cert.set_version(0x2)
		# some browsers complain if they see a cert from the same authority
		# with the same serial ==> we just use the seconds as serial.
		cert.set_serial_number(int(time.time()))
		cert.gmtime_adj_notBefore(0)
		cert.gmtime_adj_notAfter(365*24*60*60)
		cert.set_issuer(req.get_subject())
		cert.set_subject(req.get_subject())
		cert.add_extensions([ext])
		cert.set_pubkey(req.get_pubkey())
		cert.sign(pkey, "sha1")

		self.cert = cert
		self.key = pkey

		print("done.")
		print("SHA1 fingerprint:", cert.digest("sha1").decode())
		print("MD5  fingerprint:", cert.digest("md5").decode())

	def _getCert(self):
		return self.cert

	def _getKey(self):
		return self.key

	def setAuth(self, user, password, realm=None):
		if not user or not password:
			raise ServeFileException("User and password both need to be at least one character.")
		self.auth = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
		self.authrealm = realm

	def _createServer(self, handler, withv6=False):
		ThreadedHTTPServer.address_family = socket.AF_INET
		SecureThreadedHTTPServer.address_family = socket.AF_INET
		listenIp = ''
		server = None

		if withv6:
			listenIp = '::'
			ThreadedHTTPServer.address_family = socket.AF_INET6
			SecureThreadedHTTPServer.address_family = socket.AF_INET6

		if self.useSSL:
			if not self._getKey():
				self.genKeyPair()
			try:
				server = SecureThreadedHTTPServer(self._getCert(), self._getKey(),
									(listenIp, self.port), handler, bind_and_activate=False)
			except SSL.Error as e:
				raise ServeFileException("SSL error: Could not read SSL public/private key from file(s) (error was: \"%s\")" % (e[0][0][2],))
		else:
			server = ThreadedHTTPServer((listenIp, self.port), handler,
												bind_and_activate=False)

		if withv6:
			server.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

		server.server_bind()
		server.server_activate()

		return server

	def serve(self):
		self.handler = self._confAndFindHandler()
		self.server = []

		try:
			currsocktype = "IPv4"
			if self.listenIPv4:
				self.server.append(self._createServer(self.handler))
			currsocktype = "IPv6"
			if self.listenIPv6:
				self.server.append(self._createServer(self.handler, withv6=True))
		except socket.error as e:
			raise ServeFileException("Could not open %s socket: %s" % (currsocktype, e))

		if self.serveMode != self.MODE_UPLOAD:
			print("Serving \"%s\" at port %d." % (self.target, self.port))
		else:
			print("Serving \"%s\" for uploads at port %d." % (self.target, self.port))

		# print urls with local network adresses
		print("\nSome addresses %s will be available at:" % \
				("this file" if (self.serveMode != self.MODE_UPLOAD) else "the uploadform", ))
		ips = self.getIPs()
		if not ips or len(ips) == 0 or ips[0] == '':
			print("Could not find any addresses.")
		else:
			pwPart = ""
			if self.auth:
				pwPart = base64.b64decode(self.auth).decode() + "@"
			for ip in ips:
				if ":" in ip:
					ip = "[%s]" % ip
				print("\thttp%s://%s%s:%d/" % (self.useSSL and "s" or "", pwPart, ip, self.port))
		print()

		try:
			while True:
				(servers, _, _) = select.select(self.server, [], [])
				for server in servers:
					server.handle_request()
		except KeyboardInterrupt:
			for server in self.server:
				server.socket.close()

		# cleanup potential upload directory
		if self.dirCreated and len(os.listdir(self.target)) == 0:
			# created upload dir was not used
			os.rmdir(self.target)

	def _confAndFindHandler(self):
		handler = None
		if self.serveMode == self.MODE_SINGLE:
			try:
				testit = open(self.target, 'r')
				testit.close()
			except IOError as e:
				raise ServeFileException("Error: Could not open file, %r" % (str(e),))
			FileHandler.filePath = self.target
			FileHandler.fileName = os.path.basename(self.target)
			FileHandler.fileLength = os.stat(self.target).st_size
			handler = FileHandler
		elif self.serveMode == self.MODE_SINGLETAR:
			self.realTarget = os.path.realpath(self.target)
			if not os.path.exists(self.realTarget):
				raise ServeFileException("Error: Could not open file or directory.")
			TarFileHandler.target = self.realTarget
			TarFileHandler.fileName = os.path.basename(self.realTarget.rstrip("/")) + TarFileHandler.getCompressionExt()

			handler = TarFileHandler
		elif self.serveMode == self.MODE_UPLOAD:
			if os.path.isdir(self.target):
				print("Warning: Uploading to an already existing directory.")
			elif not os.path.exists(self.target):
				self.dirCreated = True
				try:
					os.mkdir(self.target)
				except (IOError, OSError) as e:
					raise ServeFileException("Error: Could not create directory '%s' for uploads, %r" % (self.target, str(e)))
			else:
				raise ServeFileException("Error: Upload directory already exists and is a file.")
			FilePutter.targetDir = os.path.abspath(self.target)
			FilePutter.maxUploadSize = self.maxUploadSize
			handler = FilePutter
		elif self.serveMode == self.MODE_LISTDIR:
			if not os.path.exists(self.target):
				raise ServeFileException("Error: Could not open file or directory.")
			if not os.path.isdir(self.target):
				raise ServeFileException("Error: '%s' is not a directory." % (self.target,))
			handler = DirListingHandler
			handler.targetDir = os.path.abspath(self.target)

		if self.auth:
			# do authentication
			AuthenticationHandler.authString = self.auth
			if self.authrealm:
				AuthenticationHandler.realm = self.authrealm
			class AuthenticatedHandler(AuthenticationHandler, handler):
				pass
			handler = AuthenticatedHandler

		if self.useSSL:
			# secure handler
			@catchSSLErrors
			class AlreadySecuredHandler(SecureHandler, handler):
				pass
			handler = AlreadySecuredHandler
		return handler


class AuthenticationHandler():
	# base64 encoded user:password string for authentication
	authString = None
	realm = "Restricted area"

	def handle_one_request(self):
		""" Overloaded function to handle one request.

		Before calling the responsible do_METHOD function, check credentials
		"""
		self.raw_requestline = self.rfile.readline()
		if not self.raw_requestline:
			self.close_connection = 1
			return
		if not self.parse_request(): # An error code has been sent, just exit
			return

		authorized = False
		if "Authorization" in self.headers:
			if self.headers["Authorization"] == ("Basic " + self.authString):
				authorized = True
		if authorized:
			mname = 'do_' + self.command
			if not hasattr(self, mname):
				self.send_error(501, "Unsupported method (%r)" % self.command)
				return
			method = getattr(self, mname)
			method()
		else:
			self.send_response(401)
			self.send_header("WWW-Authenticate", "Basic realm=\"%s\"" % self.realm)
			self.send_header("Connection", "close")
			errorMsg = "<html><head><title>401 - Unauthorized</title></head><body><h1>401 - Unauthorized</h1></body></html>"
			self.send_header("Content-Length", str(len(errorMsg)))
			self.end_headers()
			self.wfile.write(errorMsg.encode())


def main():
	parser = argparse.ArgumentParser(prog='servefile', description='Serve a single file via HTTP.')
	parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
	parser.add_argument('target', metavar='file/directory', type=str)
	parser.add_argument('-p', '--port', type=int, default=8080, \
	                    help='Port to listen on')
	parser.add_argument('-u', '--upload', action="store_true", default=False, \
	                    help="Enable uploads to a given directory")
	parser.add_argument('-s', '--max-upload-size', type=str, \
	                    help="Limit upload size in kB. Size modifiers are allowed, e.g. 2G, 12MB, 1B")
	parser.add_argument('-l', '--list-dir', action="store_true", default=False, \
	                    help="Show directory indexes and allow access to all subdirectories")
	parser.add_argument('--ssl', action="store_true", default=False, \
	                    help="Enable SSL. If no key/cert is specified one will be generated")
	parser.add_argument('--key', type=str, \
	                    help="Keyfile to use for SSL. If no cert is given with --cert the keyfile will also be searched for a cert")
	parser.add_argument('--cert', type=str, \
	                    help="Certfile to use for SSL")
	parser.add_argument('-a', '--auth', type=str, metavar='user:password', \
	                    help="Set user and password for HTTP basic authentication")
	parser.add_argument('--realm', type=str, default=None,\
	                    help="Set a realm for HTTP basic authentication")
	parser.add_argument('-t', '--tar', action="store_true", default=False, \
	                    help="Enable on the fly tar creation for given file or directory. Note: Download continuation will not be available")
	parser.add_argument('-c', '--compression', type=str, metavar='method', \
	                    default="none", \
	                    help="Set compression method, only in combination with --tar. Can be one of %s" % ", ".join(TarFileHandler.compressionMethods))
	parser.add_argument('-4', '--ipv4-only', action="store_true", default=False, \
	                    help="Listen on IPv4 only")
	parser.add_argument('-6', '--ipv6-only', action="store_true", default=False, \
	                    help="Listen on IPv6 only")

	args = parser.parse_args()
	maxUploadSize = 0

	# check for invalid option combinations/preparse stuff
	if args.max_upload_size and not args.upload:
		print("Error: Maximum upload size can only be specified when in upload mode.")
		sys.exit(1)

	if args.upload and args.list_dir:
		print("Error: Upload and dirlisting can't be enabled together.")
		sys.exit(1)

	if args.max_upload_size:
		sizeRe = re.match("^(\d+(?:[,.]\d+)?)(?:([bkmgtpe])(?:(?<!b)b?)?)?$", args.max_upload_size.lower())
		if not sizeRe:
			print("Error: Your max upload size param is broken. Try something like 3M or 2.5Gb.")
			sys.exit(1)
		uploadSize, modifier = sizeRe.groups()
		uploadSize = float(uploadSize.replace(",", "."))
		sizes = ["b", "k", "m", "g", "t", "p", "e"]
		maxUploadSize = int(uploadSize * pow(1024, sizes.index(modifier or "k")))
		if maxUploadSize < 0:
			print("Error: Your max upload size can't be negative")
			sys.exit(1)

	if args.ssl and not HAVE_SSL:
		print("Error: SSL is not available, please install pyopenssl (python3-openssl).")
		sys.exit(1)

	if args.cert and not args.key:
		print("Error: Please specify a key along with your cert.")
		sys.exit(1)

	if not args.ssl and (args.cert or args.key):
		print("Error: You need to enable ssl with --ssl when specifying certs/keys.")
		sys.exit(1)

	if args.auth:
		dpos = args.auth.find(":")
		if dpos <= 0 or dpos == (len(args.auth)-1):
			print("Error: User and password for HTTP basic authentication need to be both at least one character and have to be separated by a \":\".")
			sys.exit(1)

	if args.realm and not args.auth:
		print("You can only specify a realm when HTTP basic authentication is enabled.")
		sys.exit(1)

	if args.compression != "none" and not args.tar:
		print("Error: Please use --tar if you want to tar everything.")
		sys.exit(1)

	if args.tar and args.upload:
		print("Error: --tar mode will not work with uploads.")
		sys.exit(1)

	if args.tar and args.list_dir:
		print("Error: --tar mode will not work with directory listings.")
		sys.exit(1)

	compression = None
	if args.compression:
		if args.compression in TarFileHandler.compressionMethods:
			compression = args.compression
		else:
			print("Error: Compression mode '%s' is unknown." % args.compression)
			sys.exit(1)

	if args.ipv4_only and args.ipv6_only:
		print("You can't listen both on IPv4 and IPv6 \"only\".")
		sys.exit(1)

	if args.ipv6_only and not socket.has_ipv6:
		print("Your system does not support IPv6.")
		sys.exit(1)

	mode = None
	if args.upload:
		mode = ServeFile.MODE_UPLOAD
	elif args.list_dir:
		mode = ServeFile.MODE_LISTDIR
	elif args.tar:
		mode = ServeFile.MODE_SINGLETAR
	else:
		mode = ServeFile.MODE_SINGLE

	server = None
	try:
		server = ServeFile(args.target, args.port, mode, args.ssl)
		if maxUploadSize > 0:
			server.setMaxUploadSize(maxUploadSize)
		if args.ssl and args.key:
			cert = args.cert or args.key
			server.setSSLKeys(cert, args.key)
		if args.auth:
			user, password = args.auth.split(":", 1)
			server.setAuth(user, password, args.realm)
		if compression and compression != "none":
			server.setCompression(compression)
		if args.ipv4_only or not socket.has_ipv6:
			server.setIPv6(False)
		if args.ipv6_only:
			server.setIPv4(False)
		server.serve()
	except ServeFileException as e:
		print(e)
		sys.exit(1)
	print("Good bye.")


if __name__ == '__main__':
	main()

