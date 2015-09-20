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

"""IpCheck - Ip address Checker script

This module is a part of ipcheck script.
It contains all extensions class

"""

# Project imports


class ExtensionBase:
  """Abstract class that must be the parent of all extension handler class

  All extension are executed consecutively by the main thread, make sure that
  your extension does not block the main running more than a reasonable time

  The constructor must initialise some needed attribut but didn't receive any
  parameter
  The getter getName() is an accessor for netsav module during event handling
  The setter setLogger(logger) is an accessor for netsav module, it provide a
  door to put a logger object. It permit your trigger to put some log into the
  main logger system
  The setter setConfiguration(config) is an accessor for netsav to push the
  configuration dict into this object

  You must override them :
  The function load() is use by main module to load the trigger object itself
  The function do() is call by main module each time an event occur
  """

  # value considered as True in the config file
  BOOL_TRUE_MAP = ['true', 'TRUE', 'True', '1']

  def __init__(self):
    """Constructor : Build a specific trigger

    These attributs are pre-defined by parent class
    _logger : contain the logging object to use for logging
    _config : the configuration dictionnary which contains all configuration
              value
    _receiver : the event receiver object
    """
    self._logger = None
    self._config = None
    self._receiver = None

  def getName(self):
    """Return the name (type) of this trigger

    This is an accessor for ipcheck module
    @return [string] the name of this trigger
    """
    if self._config:
      if 'name' in self._config:
        return self._config['name']
    return 'unknown'

  def setLogger(self, logger):
    """Use to set a internal logger for this trigger

    This is an accessor for ipcheck module
    @param logger [logging] : the logger object to use
    """
    self._logger = logger

  def setConfiguration(self, config):
    """Use to setup the internal configuration dict by the netsav module

    This is an accessor for ipcheck module
    @param config [dict] : the dict which contains the key value parameters
    """
    self._config = config

  def setEventReceiver(self, obj):
    """Use to setup the internal event receiver object

    This is an accessor for ipcheck module
    @param obj [object] : the object on which call pushEvent(event)
                    to push a new event in queue
    """
    self._receiver = obj

  def load(self):
    """(To overload)Function that must load this extension instance

    API for ipcheck module
    The return value of this function determine if the extension must
    be loaded or not. If this return false, the extension will not be use
    @return [bool] :  True if load success
                        False otherwise
    """
    raise NotImplementedError('load()')

  def handle(self, event, type, data):
    """(To overload)The called function when an event must be handle by this

    API for ipcheck module
    The return value of this function will be looked and some log will be
    generated if the result is False
    This function is called each time an event happen. All event contain
    a set of information about what happen in a python dict.
    They are available by these key :
    E_BEFORE_CHECK :
    E_START : 'version_ip' 'current_ip'
    E_UPDATE : 'version_ip' 'current_ip' 'previous_ip'
    E_NOUPDATE : 'version_ip' 'current_ip'
    E_AFTER_CHECK : 'status'
    E_ERROR, T_ERROR_PERMS : 'version_ip' 'file'
    E_ERROR, T_ERROR_PERMS : 'version_ip' 'file'
    E_ERROR, T_ERROR_NOIP : 'version_ip'

    @param event [int] : the event type integer @see:Constants
    @param type [int] : the event code whic is more precise about event
                            @see:Constants
    @param data [dict] : the dict which contains the key value refer to the
                          event
    @return [bool] :  True if execution success
                        False otherwise
    """
    raise NotImplementedError('handle(event)')
