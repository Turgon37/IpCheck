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
import configparser
import logging
import os
import re
import socket

# Projet Imports
from .extension import ExtensionBase
from .constant import *


class IpCheckLoader:
    """This class design an interface object to provide access to advanced
    ipcheck feature
    """
    CORE_SECTION = 'core'

    RE_EXTENSION_SECTION = re.compile('^extension\.[a-zA-Z]+$')

    def __init__(self, logger, from_version):
        """Constructor : build an ipcheck loader
        """
        self.__ipcheck_version = from_version
        # Config object
        self.cp = configparser.ConfigParser()
        # list of trigger object for handling
        self.__extensions = []
        # internal logger
        self.__logger = logger

        self.__additionnal_datas = dict()

    def configure(self, options):
        """Load configuration for this loader object

        @param options_list [dict] : array of option key => value
        @return [bool] : True if the configuration success
                          False otherwise
        """
        if 'config_file' in options and options['config_file']:
            path = options['config_file']
            if not ( os.path.isfile(path) and os.access(path, os.R_OK) ):
                self.__logger.error('Configuration file does not exist or is not readable')
                return False
            try:
                if not self.cp.read(path):
                    raise configparser.Error('Unable to load from configuration file')
            except configparser.Error as e:
                self.__logger.error('Unable to load from configuration file : %s', str(e))
                return False

        self.__logger.debug('advanced configuration successfully loaded')
        return True

    def getConfig(self):
        """Return the defined configparser

        @return [IpCheckConfigParser] : the instancied config parser
        """
        return self.cp

    def getAdditionnalsUrls(self, ip_version):
        """Return the url list from configuration file

        @return[list] : the list of given urls
        """
        urls = []
        url = self.cp.get(self.CORE_SECTION, 'url_v'+str(ip_version), fallback='')
        if ip_version == 4:
            url += ',' + self.cp.get(self.CORE_SECTION, 'url', fallback='')
        for u in filter(lambda s: len(s), map(lambda x: x.strip(), url.split(','))):
            urls.append(u)
        return urls

    def load(self):
        """Load this trigger object with all defined trigger

        @return [bool] : True if the loading success
                          False otherwise
        """
        self.__additionnal_datas.update({
            'hostname_fqdn': socket.getfqdn(),
            'hostname': socket.gethostname(),
            'ipcheck_version': self.__ipcheck_version,
        })
        # parse all trigger section in config file
        for section in filter(lambda s: self.RE_EXTENSION_SECTION.match(s) is not None, self.cp.sections()):
            conf = dict(self.cp.items(section))
            conf['name'] = section.partition('.')[2].lower()
            ext_name = conf['name']
            # check if the trigger name contains only alpha caracters
            if not ext_name.isalpha():
                self.__logger.error('[extension] Extension name "%s" must contains only alphabetical caracters',
                                        ext_name)
                continue
            # import process
            try:
                m = __import__('ipcheckadvanced.extension.' + ext_name, fromlist=['Extension'])
                ext = m.Extension()
                if not isinstance(ext, ExtensionBase):
                    # inheritance error
                    self.__logger.error('[extension] Extension "%s" must inherit from TriggerHandler class',
                                            ext_name)
                    continue
                ext.logger = logging.getLogger('ipcheck.' + ext_name)
                ext.configuration = conf
                ext.event_receiver = self
                if ext.load():
                    self.__extensions.append(ext)
                    self.__logger.debug('[extension] loaded extension %s', ext_name)
                else:
                # loading error
                    self.__logger.error('[extension] Extension "%s" cannot be loaded', ext_name)
            except ImportError as e:
                self.__logger.error('[extension] Extension "%s" name cannot be found in extension directory %s',
                                        ext_name, str(e))
            except NotImplementedError as e:
                self.__logger.error('[extension] Extension "%s" must implement the method "%s"',
                                        ext_name, str(e))
            except KeyError as e:
                self.__logger.error('[extension] Extension "%s" require %s missing parameters see extension documentation',
                                        ext_name, str(e))
            except Exception as e:
                self.__logger.error('[extension] Extension "%s" has encountered an unknown error: %s',
                                        ext_name, str(e))
                self.__logger.exception(e)
            # # return false if no trigger have been loaded
        return self.hasExtensions()

    def hasExtensions(self):
        """Check if there is/are registered trigger

        @return [bool] : True if th trigger handler contains at least one trigger
                        False otherwise
        """
        return len(self.__extensions) > 0

    def pushEvent(self, event, type, data):
        """Push event to be trigged by all referenced trigger

        @param event [int] : the event type
        @param type [int] : the event code
        @param data [dict] : a dictionnary that will be given to all extensions
        """
        assert(data is not None)

        if event != E_ERROR and type != T_NORMAL:
            self.__logger.error('ERROR type can only be set when event is ERROR.'
                                  ' Please contact developper')
            return
        # show new event name
        if self.__logger.isEnabledFor(logging.DEBUG):
            event_name = None
            type_name = None
            for key in globals():
                if globals()[key] == event:
                    event_name = key
                if globals()[key] == type:
                    type_name = key
            if event_name and type_name:
                self.__logger.debug('handle event %s with type %s', event_name, type_name)
            else:
                self.__logger.error('handle event %s with type %s', str(event), str(type))

        # stringify all data values
        data = dict(map(lambda x: (x[0], str(x[1])), data.items()))
        data.update(self.__additionnal_datas)
        # propagate event to all registered extensions
        for ext in self.__extensions:
            try:
                if not ext.handle(event, type, data):
                    self.__logger.error('[EXT] Extension "%s" has encounter an error during handle()',
                                            ext.name)
            except KeyError as e:
                self.__logger.error('[EXT] Extension "%s" require a missing parameters "%s"',
                                        ext.name, str(e))
            except AssertionError as e:
                raise e
            except Exception as e:
                self.__logger.error('[EXT] Extension "%s" has encounter an error: %s',
                                        ext.name, str(e))
                self.__logger.exception(e)
