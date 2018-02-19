# -*- coding: utf8 -*-

import shlex
import subprocess


# command line test
def test_cmdline():
    """Must produce an error is no url was given"""
    result = subprocess.Popen(shlex.split('./ipcheck.py --help'), stdout=subprocess.PIPE)
    stdout, stderr = result.communicate()
    assert 'usage:' in stdout.decode()

    result = subprocess.Popen(shlex.split('./ipcheck.py --version'), stdout=subprocess.PIPE)
    stdout, stderr = result.communicate()
    assert 'IpCheck version' in stdout.decode()

    result = subprocess.Popen(shlex.split('./ipcheck.py --url-v4 "localhost/"'), stdout=subprocess.PIPE)
    stdout, stderr = result.communicate()
    assert result.returncode == 1
