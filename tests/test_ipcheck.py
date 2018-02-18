# -*- coding: utf8 -*-

import logging
import shlex
import shutil
import subprocess
from unittest.mock import patch

from connexionmock import ConnexionMock

import ipcheck


# command line test
def test_cmdline():
    """Must produce an error is no url was given"""
    result = subprocess.Popen(shlex.split('./ipcheck.py --help'), stdout=subprocess.PIPE)
    stdout, stderr = result.communicate()
    assert 'IpCheck version' in stdout.decode()

# URL settings
def test_without_url():
    """Must produce an error is no url was given"""
    program = ipcheck.IpCheck()
    assert program.main() == 3

@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.0'))
def test_with_good_urls(http_mock):
    """Must produce an error is bad urls were given"""
    shutil.rmtree('tmp', ignore_errors=True)

    # list
    program = ipcheck.IpCheck()
    program.configure(urls_v4=['localhost/'], tmp_directory='tmp/1')
    assert program.main() == 0

@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.0'))
def test_with_good_url(http_mock):
    """Must produce an error is bad urls were given"""
    shutil.rmtree('tmp', ignore_errors=True)

    # string
    program = ipcheck.IpCheck()
    program.configure(urls_v4='localhost/', tmp_directory='tmp')
    assert program.main() == 0

@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.0'))
def test_with_good_url_and_port(http_mock):
    """Must produce an error is bad urls were given"""
    shutil.rmtree('tmp', ignore_errors=True)

    # http
    program = ipcheck.IpCheck()
    program.configure(urls_v4='localhost:81/', tmp_directory='tmp/1')
    assert program.main() == 0

def test_with_bad_urls():
    """Must produce an error is bad urls were given"""
    # ipv4
    program = ipcheck.IpCheck()
    program.configure(urls_v4=['http://lmdaz'])
    assert program.main() == 3
    # ipv6
    program = ipcheck.IpCheck()
    program.configure(urls_v6=['http://lmdaz'])
    assert program.main() == 3

@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.0'))
def test_with_duplicate_url(http_mock, capsys):
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
@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.0'))
@patch('http.client.HTTPSConnection', return_value=ConnexionMock('0.0.0.0'))
def test_valid_address_from_url(http_mock, https_mock, capsys):
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

@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.'))
@patch('http.client.HTTPSConnection', return_value=ConnexionMock('0.0.0.'))
def test_invalid_address_from_url(http_mock, https_mock, capsys):
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

# Command hook
@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.0'))
def test_run_command_with_success(http_mock, capsys):
    """Fetch a valid IP address from urls"""
    shutil.rmtree('tmp', ignore_errors=True)

    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/1',
                        command='/bin/true')
    assert program.main() == 0

# Command hook
@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.0'))
def test_run_command_with_failure(http_mock, capsys):
    """Fetch a valid IP address from urls"""
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