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
import os
import re
import subprocess

# Projet Imports
from . import ExtensionBase
from ..constant import *

"""This extension provide a DNS lookup for DYN Host entry checking

The configuration take theses options :
  server : the ip address of DNS server to use for DNS query
  hostname : The DYN host to lookup
"""


class Extension(ExtensionBase):
  """A simple trigger skeleton

  You can use it as base for build your own trigger class
  """

  # match a exact ipv4 address
  REG_E_IPV4 = '(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])'

  # according to RFC 1123 define an hostname
  REG_E_HOST = '(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])'

  # an ip address is version 4
  REG_E_IP = '(?P<ipv4>' + REG_E_IPV4 + ')'  # IP matching

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
    self.__re_ip = re.compile(self.REG_E_IP)

  def load(self):
    """Load configuration from given dictionnary

    API for ipcheck module
    The return value of this function determine if the extension must
    be loaded or not. If this return false, the extension will not be use
    @return [bool] :  True if load success
                        False otherwise
    """
    if subprocess.call(['which', 'dig'],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) != 0:
      self._logger.error("Need the 'dig' command. Please install it')
      return False
    if 'server' in self._config:
      if re.match(self.REG_E_IPV4, self._config['server']) is None:
        self._config['server'] = '8.8.8.8'
    else:
      self._config['server'] = '8.8.8.8'

    if 'hostname' in self._config:
      if re.match(self.REG_E_HOST, self._config['hostname']) is None:
        self._logger.error("Need a valid hostname')
        return False
    else:
      self._logger.error('Need a hostname')
      return False

    return True

  def handle(self, event, type, data):
    """This function must implement the execution of your extension

    API for ipcheck module
    The return value of this function will be looked and some log will be
    generated if the result is False
    This function is called each time an event happen. All event contain
    a set of information about what happen in a python dict. They are available
    by these key :

    @param event [int] : the event type integer @see:Constants
    @param type [int] : the event code whic is more precise about event
                        @see:Constants
    @param data [dict] : the dict which contains the key value refer to the
                          event
    @return [bool] :  True if execution success
                        False otherwise
    """
    conf = self._config
    if event in [E_NOUPDATE] and type == T_NORMAL:
      out = subprocess.check_output(['dig', '+noall',
                                            '+answer',
                                            '@' + conf['server'],
                                            conf['hostname']
                                     ])
      match = self.__re_ip.search(out.decode())
      if match is None:
        self._receiver.pushEvent(E_ERROR, T_ERROR_EXTENSION, {
            'subject': 'IPv' + data['version_ip'] + ' lookup',
            'msg': 'The digchecker extension was unable to retrieve' +
            ' the registered IPv' + data['version_ip'] + ' of the hostname <' +
            conf['hostname'] + '> from publid server @' + conf['server']
        })
        return False

      ip = match.group('ipv' + data['version_ip'])
      # error between current ip and dns registered ip
      if ip is not None and ip != data['current_ip']:
        self._logger.error('Extension "' + self.getName() +
                           '" detect an invalid lookup ip')
        self._receiver.pushEvent(E_ERROR, T_CUSTOM, {
            'subject': 'IPv' + data['version_ip'] + ' lookup',
            'msg': 'An error appear with IPv' + data['version_ip'] +
                   ' address lookup.' +
                   '\nThe looked up dns address is (' + ip + ')' +
                   ' and dismatch with current IPv' + data['version_ip'] +
                   ' (' + data['current_ip'] + ')'
        })
        self._receiver.pushEvent(E_UPDATE, T_CUSTOM, data)
      # unable to get ip from dig command
      elif ip is None:
        self._receiver.pushEvent(E_ERROR, T_ERROR_EXTENSION, {
            'subject': 'IPv' + data['version_ip'] + ' lookup',
            'msg': 'The digchecker extension was unable to retrieve' +
            ' the registered IPv' + data['version_ip'] + ' of the hostname <' +
            conf['hostname'] + '> from publid server @' + conf['server']
        })
        return False
    return True
