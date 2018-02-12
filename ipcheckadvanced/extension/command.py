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
E_BEFORE_CHECK  # empty event for trigge before update
E_AFTER_CHECK  # empty event for trigger after update
E_START  # it's the first time the script is run
E_UPDATE  # the Ip address value have changed
E_NOUPDATE  # Nothing update
E_ERROR  # an error appear see type for detail
"""

# Directory from which retrieve resources file
RESOURCES_DIR = '../resources'


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
        self.__events = []
        self.__executable = None
        self.__args = []

    def load(self):
        """Load configuration from given dictionnary

        API for ipcheck module
        The return value of this function determine if the extension must
        be loaded or not. If this return false, the extension will not be use
        @return[boolean] :  True if load success
                            False otherwise
        """
        config = self.configuration
        # check event list
        if 'event' not in config:
            self.logger.error('Need a list of event')
            return False

        # load events
        for e in map(lambda e: e.strip(), config['event'].split(',')):
            if e in globals():
                self.__events.append(globals()[e])
                self.logger.debug('added event %s', e)
            else:
                self.logger.error('Event %s does not exists', e)
                return False

        # check executable presence
        if 'exec' not in config:
            self.logger.error('Need an command')
            return False
        cmd = config['exec'].strip()
        # if command is given as full path
        if cmd[0] == '/':
            if os.path.isfile(cmd) and os.access(cmd, os.X_OK):
                self.__executable = cmd
            else:
                self.logger.error('The command must be executable')
        # else try to find the command with 'which' call
        else:
            with open('/dev/null', 'w') as devnull:
                which = subprocess.call(['which', cmd],
                                stdout=devnull, stderr=devnull)
            if which == 0:
                self.__executable = cmd
            # else command is relative to the extension directory
            else:
                cmd = os.path.join(
                                os.path.dirname(os.path.realpath(__file__)),
                                RESOURCES_DIR,
                                cmd)
                if os.path.isfile(cmd) and os.access(cmd, os.X_OK):
                    self.__executable = cmd

        if self.__executable is None:
            self.logger.error('Error command not found "%s"', cmd)
            return False

        self.logger.debug('Set command ' + self.__executable)
        if 'args' in config:
            self.__args.extend(config['args'].split())
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
        if not self.__executable or event not in self.__events:
            # this event is not registered
            return True

        cmd = [self.__executable]
        # if argument are specified
        if len(self.__args):
            # loop over each arguments to try to replace strings token by
            # associated values
            cmd += map(lambda x: x.format(ip=data['current_ip']),
                        self.__args)

        self.logger.info('Run %s', cmd[0])
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                                universal_newlines=True)
        #out is currently not used
        except subprocess.CalledProcessError as e:
            self.logger.error('command "%s" has encountered an error code %s',
                                cmd[0], str(e.returncode))
            self.sendEvent(E_ERROR, T_ERROR_EXTENSION, {
                'msg': e.output,
            })
            return (e.returncode == 0)
        except Exception as e:
            self.logger.error('command %s : ', cmd[0], str(e))
            return False
        return True
