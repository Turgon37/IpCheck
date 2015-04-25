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
  CORE_SECTION = 'core'
  REG_E_EXTENSION_SECTION = '^extension\.[a-zA-Z]+$'

  # list of  value considered as True in the config file
  BOOL_TRUE_MAP = ['true', 'TRUE', 'True', '1']

  def __init__(self):
    """Constructor : init a new config parser
    """
    configparser.ConfigParser.__init__(self)
    # boolean that indicates if the configparser is available
    self.__is_config_loaded = False

  def load(self, config):
    """Try to load the configuration file

    @param[string] file : the path of the config file
    @return[boolean] : True if loading is sucess
                      False if loading fail
    """
    if config is None:
      return False
    try:
      if config in self.read(config):
        self.__is_config_loaded = True
        return True
    except configparser.Error as e:
      print(e, file=sys.stderr)
      return False
    return False

  def isLoaded(self):
    """Return the load state of this config parser

    @return(boolean) : the boolean that indicates if the config
              file is loaded or not
    """
    return self.__is_config_loaded

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
    ext_dict = dict()
    ext_dict['name'] = section.partition('.')[2].lower()
    for opt in conf:
      if re.match(ext_dict['name'] + '\.[a-zA-Z]+', opt) is not None:
        opt_name = opt.partition('.')[2]
        ext_dict[opt_name] = conf[opt]
    return ext_dict

  def getUrlList(self):
    """Return the url list from configuration file

    @return[list] : the list of given urls
    """
    url = self.get(self.CORE_SECTION, 'url')
    urls = []

    for u in url.split(','):
      u = u.strip()
      urls.append(u)
    return urls
