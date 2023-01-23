# -*- coding: utf-8 -*-
import io
import os
import pytest
import requests
import socket
import subprocess
import sys
import tarfile
import time
import urllib3
from requests.exceptions import ConnectionError

# crudly written to learn more about pytest and to have a base for refactoring


if sys.version_info.major >= 3:
    from pathlib import Path
    from urllib.parse import quote
    connrefused_exc = ConnectionRefusedError
else:
    from pathlib2 import Path
    from urllib import quote
    connrefused_exc = socket.error


def _get_port_from_env(var_name, default):
    port = int(os.environ.get(var_name, default))
    if port == 0:
        # do a one-time port selection for a free port, use it for all tests
        s = socket.socket()
        s.bind(('', 0))
        port = s.getsockname()[1]
        s.close()
    return port


SERVEFILE_DEFAULT_PORT = _get_port_from_env('SERVEFILE_DEFAULT_PORT', 0)
SERVEFILE_SECONDARY_PORT = _get_port_from_env('SERVEFILE_SECONDARY_PORT', 0)


@pytest.fixture
def run_servefile():
    instances = []

    def _run_servefile(args, **kwargs):
        if not isinstance(args, list):
            args = [args]
        if kwargs.pop('standalone', None):
            # directly call servefile.py
            servefile_path = [str(Path(__file__).parent.parent / 'servefile' / 'servefile.py')]
        else:
            # call servefile as python module
            servefile_path = ['-m', 'servefile']

        # use non-default default port, if one is given via env (and none via args)
        if '-p' not in args and '--port' not in args:
            args.extend(['-p', str(SERVEFILE_DEFAULT_PORT)])

        print("running {} with args {}".format(", ".join(servefile_path), args))
        p = subprocess.Popen([sys.executable] + servefile_path + args, **kwargs)
        instances.append(p)

        return p

    yield _run_servefile

    for instance in instances:
        try:
            instance.terminate()
        except OSError:
            pass
        instance.wait()


@pytest.fixture
def datadir(tmp_path):
    def _datadir(data, path=None):
        path = path or tmp_path
        for k, v in data.items():
            if isinstance(v, dict):
                new_path = path / k
                new_path.mkdir()
                _datadir(v, new_path)
            else:
                if hasattr(v, 'decode'):
                    v = v.decode('utf-8')  # python2 compability
                (path / k).write_text(v)

        return path
    return _datadir


def make_request(path='/', host='localhost', port=SERVEFILE_DEFAULT_PORT, method='get', protocol='http',
                 encoding='utf-8', **kwargs):
    url = '{}://{}:{}{}'.format(protocol, host, port, path)
    print('Calling {} on {} with {}'.format(method, url, kwargs))
    r = getattr(requests, method)(url, **kwargs)

    if r.encoding is None and encoding:
        r.encoding = encoding

    return r


def check_download(expected_data=None, path='/', fname=None, **kwargs):
    if fname is None:
        fname = os.path.basename(path)
    r = make_request(path, **kwargs)
    assert r.status_code == 200
    assert r.text == expected_data
    assert r.headers.get('Content-Type') == 'application/octet-stream'
    if fname:
        assert r.headers.get('Content-Disposition') == 'attachment; filename="{}"'.format(fname)
    assert r.headers.get('Content-Transfer-Encoding') == 'binary'

    return r  # for additional tests


def _retry_while(exception, function, timeout=2):
    now = time.time  # float seconds since epoch

    def wrapped(*args, **kwargs):
        timeout_after = now() + timeout
        while True:
            try:
                return function(*args, **kwargs)
            except exception:
                if now() >= timeout_after:
                    raise
                time.sleep(0.1)

    return wrapped


def _test_version(run_servefile, standalone):
    # we expect the version on stdout (python3.4+) or stderr(python2.6-3.3)
    s = run_servefile('--version', standalone=standalone, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    s.wait()
    version = s.stdout.readline().decode().strip()

    # python2 is deprecated, but we still want our tests to run for it
    # CryptographyDeprecationWarnings get in the way for this
    if 'CryptographyDeprecationWarning' in version:
        s.stdout.readline()  # ignore "from x import y" line
        version = s.stdout.readline().decode().strip()

    # hardcode version as string until servefile is a module
    assert version == 'servefile 0.5.4'


def test_version(run_servefile):
    _test_version(run_servefile, standalone=False)


def test_version_standalone(run_servefile):
    # test if servefile also works by calling servefile.py directly
    _test_version(run_servefile, standalone=True)


def test_correct_headers(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(str(p))

    r = _retry_while(ConnectionError, make_request)()
    assert r.status_code == 200
    assert r.headers.get('Content-Type') == 'application/octet-stream'
    assert r.headers.get('Content-Disposition') == 'attachment; filename="testfile"'
    assert r.headers.get('Content-Transfer-Encoding') == 'binary'


def test_redirect_and_download(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(str(p))

    # redirect
    r = _retry_while(ConnectionError, make_request)(allow_redirects=False)
    assert r.status_code == 302
    assert r.headers.get('Location') == '/testfile'

    # normal download
    check_download(data, fname='testfile')


def test_redirect_and_download_with_umlaut(run_servefile, datadir):
    data = "NÖÖT NÖÖT"
    filename = "tästføile"
    p = datadir({filename: data}) / filename
    run_servefile(str(p))

    # redirect
    r = _retry_while(ConnectionError, make_request)(allow_redirects=False)
    assert r.status_code == 302
    assert r.headers.get('Location') == '/{}'.format(quote(filename))

    # normal download
    if sys.version_info.major < 3:
        data = unicode(data, 'utf-8')
    check_download(data, fname=filename)


def test_specify_port(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile([str(p), '-p', str(SERVEFILE_SECONDARY_PORT)])

    _retry_while(ConnectionError, check_download)(data, fname='testfile', port=SERVEFILE_SECONDARY_PORT)


def test_ipv4_only(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile([str(p), '-4'])

    _retry_while(ConnectionError, check_download)(data, fname='testfile', host='127.0.0.1')

    sock = socket.socket(socket.AF_INET6)
    with pytest.raises(connrefused_exc):
        sock.connect(("::1", SERVEFILE_DEFAULT_PORT))


def test_big_download(run_servefile, datadir):
    # test with about 10 mb of data
    data = "x" * (10 * 1024 ** 2)
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(str(p))

    _retry_while(ConnectionError, check_download)(data, fname='testfile')


def test_authentication(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'

    run_servefile([str(p), '-a', 'user:password'])
    for auth in [('foo', 'bar'), ('user', 'wrong'), ('unknown', 'password')]:
        r = _retry_while(ConnectionError, make_request)(auth=auth)
        assert '401 - Unauthorized' in r.text
        assert r.status_code == 401

    _retry_while(ConnectionError, check_download)(data, fname='testfile', auth=('user', 'password'))


def test_serve_directory(run_servefile, datadir):
    d = {
        'foo': {'kratzbaum': 'cat', 'I like Cats!': 'kitteh', '&&&&&&&': 'wheee'},
        'bar': {'thisisaverylongfilenamefortestingthatthisstillworksproperly': 'jup!'},
        'noot': 'still data in here',
        'bigfile': 'x' * (10 * 1024 ** 2),
        'möwe': 'KRAKRAKRAKA',
    }
    p = datadir(d)
    run_servefile([str(p), '-l'])

    # check if all files are in directory listing
    # (could be made more sophisticated with beautifulsoup)
    for path in '/', '/../':
        r = _retry_while(ConnectionError, make_request)(path)
        for k in d:
            assert quote(k) in r.text

    for fname, content in d['foo'].items():
        _retry_while(ConnectionError, check_download)(content, '/foo/' + fname)

    r = make_request('/unknown')
    assert r.status_code == 404

    # download
    check_download('jup!', '/bar/thisisaverylongfilenamefortestingthatthisstillworksproperly')


def test_serve_relative_directory(run_servefile, datadir):
    d = {
        'foo': {'kratzbaum': 'cat', 'I like Cats!': 'kitteh', '&&&&&&&': 'wheee'},
        'bar': {'thisisaverylongfilenamefortestingthatthisstillworksproperly': 'jup!'},
        'noot': 'still data in here',
        'bigfile': 'x' * (10 * 1024 ** 2),
    }
    p = datadir(d)
    run_servefile(['../', '-l'], cwd=os.path.join(str(p), 'foo'))

    # check if all files are in directory listing
    # (could be made more sophisticated with beautifulsoup)
    for path in '/', '/../':
        r = _retry_while(ConnectionError, make_request)(path)
        for k in d:
            assert k in r.text

    for fname, content in d['foo'].items():
        check_download(content, '/foo/' + fname)

    r = make_request('/unknown')
    assert r.status_code == 404

    # download
    check_download('jup!', '/bar/thisisaverylongfilenamefortestingthatthisstillworksproperly')


def test_upload(run_servefile, tmp_path):
    data = ('this is my live now\n'
            'uploading strings to servers\n'
            'so very joyful')
    uploaddir = tmp_path / 'upload'
    # check that uploaddir does not exist before servefile is started
    assert not uploaddir.is_dir()

    run_servefile(['-u', str(uploaddir)])

    # check upload form present
    r = _retry_while(ConnectionError, make_request)()
    assert r.status_code == 200
    assert 'multipart/form-data' in r.text

    # check that servefile created the directory
    assert uploaddir.is_dir()

    # upload file
    files = {'file': ('haiku.txt', data)}
    r = make_request(method='post', files=files)
    assert 'Thanks' in r.text
    assert r.status_code == 200
    with open(str(uploaddir / 'haiku.txt')) as f:
        assert f.read() == data

    # upload file AGAIN!! (and check it is available unter a different name)
    files = {'file': ('haiku.txt', data)}
    r = make_request(method='post', files=files)
    assert r.status_code == 200
    with open(str(uploaddir / 'haiku.txt(1)')) as f:
        assert f.read() == data

    # upload file using PUT
    r = make_request("/haiku.txt", method='put', data=data)
    assert r.status_code == 201
    assert 'OK!' in r.text
    with open(str(uploaddir / 'haiku.txt(2)')) as f:
        assert f.read() == data


def test_upload_size_limit(run_servefile, tmp_path):
    uploaddir = tmp_path / 'upload'
    run_servefile(['-s', '2kb', '-u', str(uploaddir)])

    # upload file that is too big
    files = {'file': ('toobig', "x" * 2049)}
    r = _retry_while(ConnectionError, make_request)(method='post', files=files)
    assert 'Your file was too big' in r.text
    assert r.status_code == 413
    assert not (uploaddir / 'toobig').exists()

    # upload file that should fit
    # the size has to be smaller than 2kb, as the sent size also includes mime-headers
    files = {'file': ('justright', "x" * 1900)}
    r = make_request(method='post', files=files)
    assert r.status_code == 200


def test_upload_large_file(run_servefile, tmp_path):
    # small files end up in BytesIO while large files get temporary files. this
    # test makes sure we hit the large file codepath at least once
    uploaddir = tmp_path / 'upload'
    run_servefile(['-u', str(uploaddir)])

    data = "asdf" * 1024
    files = {'file': ('more_data.txt', data)}
    r = _retry_while(ConnectionError, make_request)(method='post', files=files)
    assert r.status_code == 200
    with open(str(uploaddir / 'more_data.txt')) as f:
        assert f.read() == data


def test_tar_mode(run_servefile, datadir):
    d = {
        'foo': {
            'bar': 'hello testmode my old friend',
            'baz': 'you came to test me once again',
        }
    }
    p = datadir(d)
    run_servefile(['-t', str(p / 'foo')])

    # test redirect?

    # test contents of tar file
    r = _retry_while(ConnectionError, make_request)()
    assert r.status_code == 200
    tar = tarfile.open(fileobj=io.BytesIO(r.content))
    assert len(tar.getmembers()) == 3
    assert tar.getmember('foo').isdir()
    for filename, content in d['foo'].items():
        info = tar.getmember('foo/{}'.format(filename))
        assert info.isfile
        assert tar.extractfile(info.path).read().decode() == content


def test_tar_compression(run_servefile, datadir):
    d = {'foo': 'blubb'}
    p = datadir(d)
    run_servefile(['-c', 'gzip', '-t', str(p / 'foo')])

    r = _retry_while(ConnectionError, make_request)()
    assert r.status_code == 200
    tar = tarfile.open(fileobj=io.BytesIO(r.content), mode='r:gz')
    assert len(tar.getmembers()) == 1


def test_https(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(['--ssl', str(p)])

    # fingerprint = None
    # while not fingerprint:
    #     line = s.stdout.readline()
    #     print(line)
    #     # if we find this line we went too far...
    #     assert not line.startswith("Some addresses this file will be available at")

    #     if line.startswith("SHA1 fingerprint"):
    #         fingerprint = line.replace("SHA1 fingerprint: ", "").strip()
    #         break

    # assert fingerprint
    urllib3.disable_warnings()
    _retry_while(ConnectionError, check_download)(data, protocol='https', verify=False)


def test_https_big_download(run_servefile, datadir):
    # test with about 10 mb of data
    data = "x" * (10 * 1024 ** 2)
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(['--ssl', str(p)])

    urllib3.disable_warnings()
    _retry_while(ConnectionError, check_download)(data, protocol='https', verify=False)


def test_abort_download(run_servefile, datadir):
    data = "x" * (10 * 1024 ** 2)
    p = datadir({'testfile': data}) / 'testfile'
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    proc = run_servefile(str(p), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)

    # provoke a connection abort
    # hopefully the buffers will not fill up with all of the 10mb
    sock = socket.socket(socket.AF_INET)
    _retry_while(connrefused_exc, sock.connect)(("localhost", SERVEFILE_DEFAULT_PORT))
    sock.send(b"GET /testfile HTTP/1.0\n\n")
    resp = sock.recv(100)
    assert resp != b''
    sock.close()
    time.sleep(0.1)
    proc.kill()
    out = proc.stdout.read().decode()
    assert "127.0.0.1 ABORTED transmission" in out
