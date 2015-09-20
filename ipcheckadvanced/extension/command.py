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
import subprocess
import os

# Projet Imports
from . import ExtensionBase
from ..constant import *

"""This extension provide a command execution on IpCheck Events

The configuration take theses options :
  exec : the name/path of the command to run
  args : the argument to pass to the command during
  event : the name list of event when the command will be executed

event can be :
'E_BEFORE_CHECK',  # empty event for trigge before update
'E_AFTER_CHECK',  # empty event for trigger after update
'E_START',  # it's the first time the script is run
'E_UPDATE',  # the Ip address value have changed
'E_NOUPDATE',  # Nothing update
'E_ERROR'  # an error appear see type for detail

"""

# Directory from which retrieve resources file
RESOURCES_DIR = '/../resources/'


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
    self.event = []
    self.executable = None
    self.args = []

  def load(self):
    """Load configuration from given dictionnary

    API for ipcheck module
    The return value of this function determine if the extension must
    be loaded or not. If this return false, the extension will not be use
    @return[boolean] :  True if load success
                        False otherwise
    """
    # check event list
    if 'event' not in self._config:
      return False
    events = self._config['event'].split(',')
    for e in events:
      e = e.strip()
      if e in globals():
        self.event.append(globals()[e])
      else:
        return False
    # check executable presence
    if 'exec' not in self._config:
      return False
    cmd = self._config['exec'].strip()
    # if command is given as full path
    if cmd[0] == '/':
      if os.path.isfile(cmd) and os.access(cmd, os.X_OK):
        self.executable = cmd
    # else try to find the command with 'which' call
    elif subprocess.call(['which', cmd],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL) == 0:
      self.executable = cmd
    # else command is relative to the extension directory
    else:
      cmd = os.path.dirname(os.path.realpath(__file__)) + RESOURCES_DIR + cmd
      if os.path.isfile(cmd) and os.access(cmd, os.X_OK):
        self.executable = cmd

    if self.executable is None:
      self._logger.error('Error command not found "' + cmd + '"')
      return False
    else:
      self._logger.debug('Set command ' + self.executable)

    if 'args' in self._config:
      self.args += self._config['args'].split()

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
    # if the current event is in the allowed list
    if self.executable and event in self.event:
      # if argument are specified
      if len(self.args):
        # loop over each arguments to try to replace strings token by
        # associated values
        for index in range(len(self.args)):
          self.args[index] = self.args[index].format(
              ip=data['current_ip']
          )
      self._logger.info('Run ' + self.executable)
      try:
        out = subprocess.check_output([self.executable] + self.args,
                                      stderr=subprocess.STDOUT,
                                      universal_newlines=True)
        #out is currently not used
      except subprocess.CalledProcessError as e:
        self._logger.error('command "' + self.executable +
                           '" encount an error : ' + str(e.returncode))
        self._receiver.pushEvent(E_ERROR, T_ERROR_EXTENSION, {
            'msg': e.output,
            'extension': self.getName()
        })
        return (e.returncode == 0)
      except Exception as e:
        self._logger.error('command' + self.executable + e)
        return False
      return True
    # this event is not registered
    else:
      return True
