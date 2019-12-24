import io
import os
import pytest
import requests
import subprocess
import tarfile
import time
import urllib3

# crudly written to learn more about pytest and to have a base for refactoring


@pytest.fixture
def run_servefile():
    instances = []

    def _run_servefile(args, **kwargs):
        if not isinstance(args, list):
            args = [args]
        print("running with args", args)
        p = subprocess.Popen(['servefile'] + args, **kwargs)
        time.sleep(kwargs.get('timeout', 0.3))
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
                    v = v.decode()  # python2 compability
                (path / k).write_text(v)

        return path
    return _datadir


def make_request(path='/', host='localhost', port=8080, method='get', protocol='http', **kwargs):
    url = '{}://{}:{}{}'.format(protocol, host, port, path)
    print('Calling {} on {} with {}'.format(method, url, kwargs))
    r = getattr(requests, method)(url, **kwargs)

    return r


def check_download(expected_data=None, path='/', fname=None, status_code=200, **kwargs):
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


def test_version(run_servefile):
    # we expect the version on stdout (python3.4+) or stderr(python2.6-3.3)
    s = run_servefile('--version', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    s.wait()
    version = s.stdout.readline().decode().strip()

    # hardcode version as string until servefile is a module
    assert version == 'servefile 0.4.4'


def test_correct_headers(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(str(p))

    r = make_request()
    assert r.status_code == 200
    assert r.headers.get('Content-Type') == 'application/octet-stream'
    assert r.headers.get('Content-Disposition') == 'attachment; filename="testfile"'
    assert r.headers.get('Content-Transfer-Encoding') == 'binary'


def test_redirect_and_download(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(str(p))

    # redirect
    r = make_request(allow_redirects=False)
    assert r.status_code == 302
    assert r.headers.get('Location') == '/testfile'

    # normal download
    check_download(data, fname='testfile')


def test_specify_port(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile([str(p), '-p', '8081'])

    check_download(data, fname='testfile', port=8081)


def test_ipv4_only(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile([str(p), '-4'])

    check_download(data, fname='testfile', host='127.0.0.1')


def test_big_download(run_servefile, datadir):
    # test with about 10 mb of data
    data = "x" * (10 * 1024 ** 2)
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(str(p))

    check_download(data, fname='testfile')


def test_authentication(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'

    run_servefile([str(p), '-a', 'user:password'])
    for auth in [('foo', 'bar'), ('user', 'wrong'), ('unknown', 'password')]:
        r = make_request(auth=auth)
        assert '401 - Unauthorized' in r.text
        assert r.status_code == 401

    check_download(data, fname='testfile', auth=('user', 'password'))


def test_serve_directory(run_servefile, datadir):
    d = {
        'foo': {'kratzbaum': 'cat', 'I like Cats!': 'kitteh', '&&&&&&&': 'wheee'},
        'bar': {'thisisaverylongfilenamefortestingthatthisstillworksproperly': 'jup!'},
        'noot': 'still data in here',
        'bigfile': 'x' * (10 * 1024 ** 2),
    }
    p = datadir(d)
    run_servefile([str(p), '-l'])

    # check if all files are in directory listing
    # (could be made more sophisticated with beautifulsoup)
    for path in '/', '/../':
        r = make_request(path)
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

    # check that servefile created the directory
    assert uploaddir.is_dir()

    # check upload form present
    r = make_request()
    assert r.status_code == 200
    assert 'multipart/form-data' in r.text

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


def test_upload_size_limit(run_servefile, tmp_path):
    uploaddir = tmp_path / 'upload'
    run_servefile(['-s', '2kb', '-u', str(uploaddir)])

    # upload file that is too big
    files = {'file': ('toobig', "x" * 2049)}
    r = make_request(method='post', files=files)
    assert 'Your file was too big' in r.text
    assert r.status_code == 413
    assert not (uploaddir / 'toobig').exists()

    # upload file that should fit
    # the size has to be smaller than 2kb, as the sent size also includes mime-headers
    files = {'file': ('justright', "x" * 1900)}
    r = make_request(method='post', files=files)
    assert r.status_code == 200


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
    r = make_request()
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

    r = make_request()
    assert r.status_code == 200
    tar = tarfile.open(fileobj=io.BytesIO(r.content), mode='r:gz')
    assert len(tar.getmembers()) == 1


def test_https(run_servefile, datadir):
    data = "NOOT NOOT"
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(['--ssl', str(p)])
    time.sleep(0.2)  # time for generating ssl certificates

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
    check_download(data, protocol='https', verify=False)

def test_https_big_download(run_servefile, datadir):
    # test with about 10 mb of data
    data = "x" * (10 * 1024 ** 2)
    p = datadir({'testfile': data}) / 'testfile'
    run_servefile(['--ssl', str(p)])
    time.sleep(0.2)  # time for generating ssl certificates

    urllib3.disable_warnings()
    check_download(data, protocol='https', verify=False)
