# -*- coding: utf8 -*-

import http.client
import logging
import shlex
import shutil
import socket
import ssl
import subprocess
from unittest.mock import patch, Mock

from .mocks.connexionmock import createHTTPConnectionMock, createHTTPSConnectionMock

import ipcheck


# URL settings
def test_without_url():
    """Must produce an error is no url was given"""
    program = ipcheck.IpCheck()
    assert program.main() == 3

@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_with_good_urls():
    """Must produce an error is bad urls were given"""
    shutil.rmtree('tmp', ignore_errors=True)

    # list
    program = ipcheck.IpCheck()
    program.configure(urls_v4=['localhost/'], tmp_directory='tmp/1')
    assert program.main() == 0

    # conn.getresponse.assert_called_once()

@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_with_good_url():
    """Must produce an error is bad urls were given"""
    shutil.rmtree('tmp', ignore_errors=True)

    # string
    program = ipcheck.IpCheck()
    program.configure(urls_v4='localhost/', tmp_directory='tmp')
    assert program.main() == 0

@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_with_good_url_and_port():
    """Must produce an error is bad urls were given"""
    shutil.rmtree('tmp', ignore_errors=True)

    # http
    program = ipcheck.IpCheck()
    program.configure(urls_v4='localhost:81/query', tmp_directory='tmp/1')
    assert program.main() == 0

def test_with_bad_urls():
    """Must produce an error is bad urls were given"""
    # ipv4
    program = ipcheck.IpCheck()
    program.configure(urls_v4=['http://lmdaz'])
    assert program.main() == 3

    program = ipcheck.IpCheck()
    program.configure(urls_v4=['ftp://lmdaz'])
    assert program.main() == 3

    # ipv6
    program = ipcheck.IpCheck()
    program.configure(urls_v6=['http://lmdaz'])
    assert program.main() == 3

@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_with_duplicate_url(capsys):
    """The url must be fetched only once"""
    shutil.rmtree('tmp', ignore_errors=True)

    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/', 'http://0.0.0.0/'], tmp_directory='tmp/')
    assert program.main() == 0
    out, err = capsys.readouterr()
    assert 'url already exists' in out
    assert out.count('query url http://0.0.0.0/') == 1

# TMP DIRECTORY settings
def test_with_bad_tmp_directory_path_in_stdout(capsys):
    """Must produce an error in stdout if the temporary directory cannot be created"""
    program = ipcheck.IpCheck()
    program.configure(urls_v4=['http://0.0.0.0/'], tmp_directory='/impossible/path')
    assert program.main() == 1
    out, err = capsys.readouterr()
    assert 'Unable to create the required directory' in out

def test_with_bad_tmp_directory_path_in_stderr(capsys):
    """Must produce an error in stderr if the temporary directory cannot be created"""
    program = ipcheck.IpCheck()
    program.configure(urls_v4=['http://0.0.0.0/'],
                        tmp_directory='/impossible/path',
                        verbose=-1,
                        errors_to_stderr=True)
    assert program.main() == 1
    out, err = capsys.readouterr()
    assert 'Unable to create the required directory' in err

# HTTP fetchs
@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
@patch('http.client.HTTPSConnection', createHTTPSConnectionMock('0.0.0.0'))
def test_valid_address_from_url(capsys):
    """Fetch a valid IP address from urls"""
    shutil.rmtree('tmp', ignore_errors=True)

    # http
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/1/')
    assert program.main() == 0

    # https
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['https://0.0.0.0/'], tmp_directory='tmp/2/')
    assert program.main() == 0

@patch('http.client.HTTPConnection', createHTTPConnectionMock('Not authorized', 401))
@patch('http.client.HTTPSConnection', createHTTPSConnectionMock('0.0.0.0', 200))
def test_unautorized_http_url(capsys):
    """Unable to fetch from urls because of missing credentials"""
    shutil.rmtree('tmp', ignore_errors=True)

    # https
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/1/')
    assert program.main() == 1

    out, err = capsys.readouterr()
    assert 'may require an authentification' in out

    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['https://user:password@0.0.0.0/'], tmp_directory='tmp/2/')
    assert program.main() == 0

@patch('http.client.HTTPSConnection', createHTTPSConnectionMock('0.0.0.0'))
@patch('ssl._create_unverified_context', return_value=Mock(spec=ssl.SSLContext))
def test_insecure_https_address_from_url(ssl_context_mock, capsys):
    """Fetch a valid IP address from urls"""
    shutil.rmtree('tmp', ignore_errors=True)

    # https
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['https://0.0.0.0/'], tls_insecure=True, tmp_directory='tmp/1/')
    assert program.main() == 0

    ssl._create_unverified_context.assert_called_once_with()

@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.'))
@patch('http.client.HTTPSConnection', createHTTPSConnectionMock('0.0.0.'))
def test_invalid_address_from_url(capsys):
    """Fetch an invalid IP address from urls, must generate an error"""
    shutil.rmtree('tmp', ignore_errors=True)

    # http
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/1')
    assert program.main() == 1

    # https
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['https://0.0.0.0/'], tmp_directory='tmp/2')
    assert program.main() == 1


# HTTP exeception
def test_http_error_from_url(capsys):
    """Catch an HttpError from urls"""
    shutil.rmtree('tmp', ignore_errors=True)

    with patch('http.client.HTTPConnection',
                createHTTPConnectionMock('0.0.0.0', raise_=http.client.HTTPException)) as http_mock:
        # http
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/1/')
        assert program.main() == 1

    with patch('http.client.HTTPSConnection',
                createHTTPSConnectionMock('0.0.0.0', raise_=socket.gaierror)) as http_mock:
        # https
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['https://0.0.0.0/'], tmp_directory='tmp/2/')
        assert program.main() == 1

    with patch('http.client.HTTPSConnection',
                createHTTPSConnectionMock('0.0.0.0', raise_=ssl.SSLError)) as http_mock:
        # https
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['https://0.0.0.0/'], tmp_directory='tmp/3/')
        assert program.main() == 1
        out, err = capsys.readouterr()
        assert 'You can override this by using --insecure' in out

# Command hook
@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_run_command_with_success(capsys):
    """Run a command with success"""
    shutil.rmtree('tmp', ignore_errors=True)

    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/1',
                        command='/bin/true')
    assert program.main() == 0

# Command hook
@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_run_command_with_failure(capsys):
    """Run a command with success"""
    shutil.rmtree('tmp', ignore_errors=True)

    # http
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/1',
                        command='/bin/false')
    assert program.main() == 1

    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/2',
                        command='/bin/nonexistent')
    assert program.main() == 1


# IP
def test_run_ip_checking_with_good_value(capsys):
    """Run a command with success"""
    shutil.rmtree('tmp', ignore_errors=True)

    with patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0')) as http_mock:
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp')
        assert program.main() == 0

    with patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0')) as http_mock:
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp')
        assert program.main() == 0

def test_run_ip_checking_with_bad_value(capsys):
    """Run a command with success"""
    shutil.rmtree('tmp', ignore_errors=True)

    with patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0')) as http_mock:
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp')
        assert program.main() == 0

    with open('tmp/ipv4', 'w') as tmp:
        tmp.write('0.0.0')

    with patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0')) as http_mock:
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp')
        assert program.main() == 1

def test_run_ip_checking_with_changed_value(capsys):
    """Run a command with success"""
    shutil.rmtree('tmp', ignore_errors=True)

    with patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0')) as http_mock:
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp')
        assert program.main() == 0

    with open('tmp/ipv4', 'w') as tmp:
        tmp.write('0.0.0.1')

    with patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0')) as http_mock:
        program = ipcheck.IpCheck()
        program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp')
        assert program.main() == 0
