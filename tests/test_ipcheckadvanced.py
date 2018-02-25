# -*- coding: utf8 -*-

import argparse
import configparser
import os
import shutil
from unittest.mock import patch

# Project tests imports
from .mocks.connexionmock import createHTTPConnectionMock, createHTTPSConnectionMock

# Project imports
import ipcheck
import ipcheckadvanced


# CLI settings
def test_argparse_extension(capsys):
    """Must """
    parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)

    # Load advanced parameters
    if ipcheckadvanced:
        ipcheckadvanced.configureArgParser(parser)
    parser.print_usage()

    out, err = capsys.readouterr()
    assert '--config' in out

# URL settings
@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_valid_url_from_config(capsys):
    """Fetch a valid IP address from urls"""
    shutil.rmtree('tmp', ignore_errors=True)
    os.mkdir('tmp')

    config = configparser.ConfigParser()
    config['core'] = {}
    config['core']['url_v4'] = '0.0.0.0/'

    with open('tmp/config.ini', 'w') as configfile:
        config.write(configfile)

    # http
    program = ipcheck.IpCheck()
    program.configure(verbose=1, tmp_directory='tmp', config_file='tmp/config.ini')
    assert program.main() == 0

# config settings
@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_invalid_config_file(capsys):
    """Fetch a valid IP address from urls"""
    shutil.rmtree('tmp', ignore_errors=True)
    os.mkdir('tmp')

    with open('tmp/config.ini', 'w') as configfile:
        configfile.write('[core\nurl_v4 = 1/')

    # http
    program = ipcheck.IpCheck()
    program.configure(verbose=1, tmp_directory='tmp', config_file='tmp/config.ini')
    assert program.main() == 3
