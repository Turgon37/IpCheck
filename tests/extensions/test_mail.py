# -*- coding: utf8 -*-

import argparse
import configparser
import os
import shutil
from unittest.mock import patch

# Project tests imports
from ..mocks.connexionmock import createHTTPConnectionMock, createHTTPSConnectionMock

# Project imports
import ipcheck
import ipcheckadvanced


@patch('http.client.HTTPConnection', createHTTPConnectionMock('0.0.0.0'))
def test_mail_loading(capsys):
    """Just load the mail extension"""
    shutil.rmtree('tmp', ignore_errors=True)
    os.mkdir('tmp')

    config = configparser.ConfigParser()
    config['core'] = {}
    config['core']['url_v4'] = '0.0.0.0/'
    config['extension.mail'] = {}

    with open('tmp/config.ini', 'w') as configfile:
        config.write(configfile)

    # http
    program = ipcheck.IpCheck()
    program.configure(verbose=1, tmp_directory='tmp', config_file='tmp/config.ini')
    assert program.main() == 0
