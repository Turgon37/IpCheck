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
import logging


# Projet Imports
from .config import IpCheckConfigParser
from .extension import ExtensionBase
from .constant import *


class IpCheckLoader:
  """This class design an interface object to provide access to advanced
   ipcheck feature
  """

  def __init__(self, logger):
    """Constructor : build an ipcheck loader
    """
    # Config object
    self.cp = IpCheckConfigParser()
    # list of trigger object for handling
    self.__l_extension = []
    # internal logger
    self.__logger = logger

  def configure(self, options_list):
    """Load configuration for this loader object

    @param options_list [dict] : array of option key => value
    @return [bool] : True if the configuration success
                      False otherwise
    """
    for opt in options_list:
      if opt[0] == '--config':
        if not self.cp.load(opt[1].lstrip('=')):
          self.__logger.error('Unable to load from configuration file')
          return False
        else:
          self.__logger.debug('advanced configuration successfully loaded')
    return True

  def getConfig(self):
    """Return the defined configparser

    @return [IpCheckConfigParser] : the instancied config parser
    """
    return self.cp

  def load(self):
    """Load this trigger object with all defined trigger

    @return [bool] : True if the loading success
                      False otherwise
    """
    if not self.cp.isLoaded():
      return False
    # parse all trigger section in config file
    for section in self.cp.getExtensionSections():
      # retrieve the current trigger configuration dict
      param = self.cp.getExtensionConfigDict(section)
      ext_name = param['name']
      # check if the trigger name contains only alpha caracters
      if not param['name'].isalpha():
        self.__logger.error('[extension] Extension name "' + ext_name +
                            '" must contains only alphabetical caracters')
        continue
      # import process
      try:
        m = __import__('ipcheckadvanced.extension.' + ext_name,
                       fromlist=['Extension'])
        ext = m.Extension()
        if not isinstance(ext, ExtensionBase):
          # inheritance error
          self.__logger.error('[EXT] Extension "' + ext_name +
                              '" must inherit from TriggerHandler class')
          continue
        ext.setLogger(logging.getLogger('ipcheck.' + ext_name))
        ext.setConfiguration(param)
        ext.setEventReceiver(self)
        if ext.load():
          self.__l_extension.append(ext)
          self.__logger.debug('[EXT] Loaded extension ' + ext_name)
        else:
          # loading error
          self.__logger.error('[EXT] Ext "' + ext_name +
                              '" cannot be load')
      except ImportError as e:
        self.__logger.error('[EXT] Ext "' + ext_name +
                            '" name cannot be found in extension directory ' +
                            str(e))
      except NotImplementedError as e:
        self.__logger.error('[EXT] Ext "' + ext_name +
                            '" must implement the method "' + str(e) + '"')
      except KeyError as e:
        self.__logger.error('[EXT] Ext "' + ext_name + '" require ' +
                            str(e) + ' missing parameters see extension ' +
                            'documentation')
      except Exception as e:
        self.__logger.error('[EXT] Ext "' + ext_name +
                            '" has encounter an unknown error: ' + str(e))

    # return false if no trigger have been loaded
    return self.hasExtension()

  def hasExtension(self):
    """Check if there is/are registered trigger

    @return [bool] : True if th trigger handler contains at least one trigger
                       False otherwise
    """
    return len(self.__l_extension) > 0

  def pushEvent(self, event, type, data):
    """Push event to be trigged by all referenced trigger

    @param event [int] : the event type
    @param type [int] : the event code
    @param data [dict] : a dictionnary that will be given to all extensions
    """
    assert(data is not None)

    if event != E_ERROR and type != T_NORMAL:
      self.__logger.error('ERROR type can only be set when event is ERROR.' +
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
        self.__logger.debug('handle event ' + event_name +
                            ' with type ' + type_name)
      else:
        self.__logger.debug('handle event ' + str(event) +
                            ' with type ' + str(type))
    # stringify all data values
    for key in data:
      data[key] = str(data[key])
    # propagate event to all registered extensions
    for ext in self.__l_extension:
      try:
        if not ext.handle(event, type, data):
          self.__logger.error('[EXT] Extension "' + ext.getName() +
                              '" has encounter an error during handle()')
      except KeyError as e:
        self.__logger.error('[EXT] Extension "' + ext.getName() +
                            '" require a missing parameters "' + str(e) +
                            '" see trigger documentation')
      except Exception as e:
        self.__logger.error('[EXT] Extension "' + ext.getName() +
                            '" has encounter an error: ' + str(e))
