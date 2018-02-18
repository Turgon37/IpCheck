# -*- coding: utf8 -*-

from unittest.mock import patch


from connexionmock import ConnexionMock

import ipcheck


# URL settings
def test_without_url():
    """Must produce an error is no url was given"""
    program = ipcheck.IpCheck()
    assert program.main() == 3

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

@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.0'))
@patch('http.client.HTTPSConnection', return_value=ConnexionMock('0.0.0.0'))
def test_valid_address_from_url(http_mock, https_mock, capsys):
    """Fetch a valid IP address from urls"""
    # http
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/')
    assert program.main() == 0

    # https
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['https://0.0.0.0/'], tmp_directory='tmp/')
    assert program.main() == 0

@patch('http.client.HTTPConnection', return_value=ConnexionMock('0.0.0.'))
@patch('http.client.HTTPSConnection', return_value=ConnexionMock('0.0.0.'))
def test_invalid_address_from_url(http_mock, https_mock, capsys):
    """Fetch an invalid IP address from urls, must generate an error"""
    # http
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['http://0.0.0.0/'], tmp_directory='tmp/')
    assert program.main() == 1

    # https
    program = ipcheck.IpCheck()
    program.configure(verbose=1, urls_v4=['https://0.0.0.0/'], tmp_directory='tmp/')
    assert program.main() == 1
