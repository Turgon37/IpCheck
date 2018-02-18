# -*- coding: utf8 -*-

import argparse
from unittest.mock import patch

# Project tests imports
from connexionmock import ConnexionMock

# Project imports
import ipcheck
import ipcheckadvanced


# URL settings
def test_argparse_extension(capsys):
    """Must """
    parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)

    # Load advanced parameters
    if ipcheckadvanced:
        ipcheckadvanced.configureArgParser(parser)
    parser.print_usage()

    out, err = capsys.readouterr()
    assert '--config' in out
