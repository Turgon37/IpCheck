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

"""Ip Check configparser class

It provide a parser class which extend the original ConfigParser class
in order to add some function, expecially for retrieving directly
several configuration keys in a dict
"""

# System imports
import configparser
import re
import sys

# Global project declarations


class IpCheckConfigParser(configparser.ConfigParser):
  """(extend ConfigParser) Set specific function for configuration file parsing

  Refer to the config file
  provide more function to parse directly the config file as project's needed
  """
  
  REG_E_EXTENSION_SECTION = '^extension\.[a-zA-Z]+$'

  # list of  value considered as True in the config file
  BOOL_TRUE_MAP = ['true', 'TRUE', 'True', '1']


  def getExtensionSections(self):
    """Return the list of trigger section name

    @return(list) : the list of trigger sections name
    """
    c_list = []
    for sect in self.sections():
      if re.match(self.REG_E_EXTENSION_SECTION, sect) is not None:
        c_list.append(sect)
    return c_list

  def getExtensionConfigDict(self, section):
    """Return the dict which contains all value which match with the 'name.'

    @return[dict] : the parameters dict
    """
    conf = dict(self.items(section))
    conf['name'] = section.partition('.')[2].lower()
    return conf
