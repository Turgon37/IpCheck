# -*- coding: utf8 -*-

# This file is a part of ipcheck
#
# Copyright (c) 2015 Pierre GINDRAUD
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# System imports
# Put here your system needed imports


# Projet Imports
from .base import ExtensionBase
from ..constant import *


class Extension(ExtensionBase):
  """A simple trigger skeleton

  You can use it as base for build your own trigger class
  """

  def __init__(self):
    """(override)Default constructor:

    !! Keep the call to parent constructor
    Put here some attribut initialisation

    These attributs are pre-defined by parent class
    _logger : contain the logging object to use for logging
    _config : the configuration dictionnary which contains all configuration
              value
    _receiver : the event receiver object
    """
    ExtensionBase.__init__(self)

  def load(self):
    """Load configuration from given dictionnary

    API for ipcheck module
    The return value of this function determine if the extension must
    be loaded or not. If this return false, the extension will not be use
    @return[boolean] :  True if load success
                        False otherwise
    """
    raise NotImplementedError('load()')

  def handle(self, event, type, data):
    """This function must implement the execution of your extension

    API for ipcheck module
    The return value of this function will be looked and some log will be
    generated if the result is False
    This function is called each time an event happen. All event contain
    a set of information about what happen in a python dict. They are available
    by these key :

    @param[int] event : the event type integer @see:Constants
    @param[int] type : the event code whic is more precise about event
                            @see:Constants
    @param[dict] data : the dict which contains the key value refer to the
                          event
    @return[boolean] :  True if execution success
                        False otherwise
    """
    raise NotImplementedError('handle(event, type, data)')
