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

    RE_IP = re.compile(REG_E_IP)
    RE_HOST = re.compile(REG_E_HOST)

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

    def getDefaultConfig(self):
        """Return the default configuration items for this extension
        """
        return super(Extension, self).getDefaultConfig({
            'server': '8.8.8.8',
            'msg_subject': 'IPv{version_ip} digchecker lookup',
        })

    def load(self):
        """Load configuration from given dictionnary

        API for ipcheck module
        The return value of this function determine if the extension must
        be loaded or not. If this return false, the extension will not be use
        @return [bool] :  True if load success
                            False otherwise
        """
        with open("/dev/null", "w") as devnull:
            try:
                subprocess.call(['which', 'dig'],
                                    stdout=devnull,
                                    stderr=devnull)
            except subprocess.CalledProcessError:
                self.logger.error("Need the 'dig' command. Please install it")
                return False

        config = self.getDefaultConfig()
        config.update(self.configuration)
        if 'server' in config and self.RE_IP.match(config['server']) is None:
            config['server'] = '8.8.8.8'

        if 'hostname' in config:
            if self.RE_HOST.match(config['hostname']) is None:
                self._logger.error('Need a valid hostname')
                return False
        else:
            self._logger.error('Need a hostname')
            return False

        self.configuration = config
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
        conf = self.configuration
        if event not in [E_NOUPDATE] or type != T_NORMAL:
            return True

        out = subprocess.check_output(['dig', '+noall', '+answer',
                                            '@' + conf['server'],
                                            conf['hostname'] ])
        match = self.RE_IP.search(out.decode())
        if match is None:
            self.sendEvent(E_ERROR, T_ERROR_EXTENSION, {
                'subject': conf.get('msg_subject'),
                'msg': ('The digchecker extension was unable to retrieve ' +
                    'the registered IPv{version_ip} of the hostname <{hostname}> '+
                    'from public server @{digchecker_server}'),
                'digchecker_server': conf['server'],
            })
            return False

        ip = match.group('ipv' + data['version_ip'])
        # error between current ip and dns registered ip
        if ip and ip != data['current_ip']:
            self.logger.error('Inconsistency detected between local ip and lookup ip')
            self.sendEvent(E_ERROR, T_CUSTOM, {
                'subject': conf.get('msg_subject'),
                'msg': ('An error appear with IPv{version_ip} address lookup.' +
                   '\nThe looked up address is {digchecker_lookup_ip} ' +
                   ' and dismatch with current IPv{version_ip} {current_ip}'),
                'digchecker_lookup_ip': ip,
            })
            # trigger manually an new update
            self.sendEvent(E_UPDATE, T_NORMAL, data)
        # unable to get ip from dig command
        elif ip is None:
            self.sendEvent(E_ERROR, T_ERROR_EXTENSION, {
                'subject': conf.get('msg_subject'),
                'msg': ('The digchecker extension was unable to retrieve the ' +
                    'registered IPv{version_ip} of the hostname <{hostname}> ' +
                    'from public server @{digchecker_server}')
            })
            return False
        return True
