#!/usr/bin/python3
# -*- coding: utf8 -*-

# This file is a part of DynUpdate
#
# Copyright (c) 2014-2015 Pierre GINDRAUD
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

"""DynUpdate program

A simple dyndns client
https://github.com/Turgon37/DynUpdate
"""

# System imports
from base64 import b64encode
import getopt
from http.client import HTTPConnection
import logging
import re
import socket
import sys

# Global project declarations
version = '1.0.1'


class DynUpdate:
  """An instance of a dyn client

  This class represent a instance of a dyn dns client until it make
  his http query to update a remote dns server entry
  """

  # match a exact ipv4 address
  REG_E_IPV4 = '(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])'

  # an ip address is version 4
  REG_E_IP = '^(?P<ipv4>' + REG_E_IPV4 + ')$'  # IP matching

  def __init__(self):
    """Constructor : Build an launcher for dynupdate
    """
    # Network required
    self.username = ''
    self.password = ''
    self.server = ''
    self.port = 80
    self.url = '/nic/update'
    # re match object
    self.__re_ip = re.compile(self.REG_E_IP)
    # logger system
    self.__logger = logging.getLogger('dynupdate')
    self.__logger.setLevel('INFO')
    hdlr = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(levelname)s : %(message)s")
    hdlr.setFormatter(formatter)
    self.__logger.addHandler(hdlr)

    # DYNDNS protocol
    # for detail see https://help.dyn.com/remote-access-api/perform-update/
    self.__fields = dict()

    # Identify update type
    # "dyndns", "statdns"
    self.__fields['system'] = 'dyndns'

    # A comma separated list of host to update (max 20)
    self.__fields['hostname'] = ''

    # The IP address to set.
    # If not set or incorrect the server will choose himself an IP
    self.__fields['myip'] = ''

    # Parameter enables or disables wildcards for this host.
    # Values : "ON","NOCHG","OFF"
    self.__fields['wildcard'] = 'NOCHG'

    # Specify an eMail eXchanger
    self.__fields['mx'] = ''

    # Requests the MX in the previous parameter to be set up as a backup MX
    # by listing the host itself as an MX with a lower preference value.
    # Values : "ON","NOCHG","OFF"
    self.__fields['backmx'] = 'NOCHG'

    # Set the hostname to offline mode
    # "YES" turn on offline redirect for host
    # "NOCHG" no make change
    self.__fields['offline'] = 'NOCHG'

    # No already use
    self.__fields['url'] = ''

  @staticmethod
  def showVersion():
    """Print the program version
    """
    print("netsav version v" + netsav.version)

  def showUsage(self):
    """Prints command line options
    """
    print('Usage: ' + sys.argv[0] + ' REQUIRED [OPTIONS...]')
    print("""
Dyn update client v""" + version + """
Use DYNDNS protocol for updating a dynhost with a new ip address

Required :
    -a, --address=IP_ADDRESS   set the IP address to use for update
    -h, --hostname=HOSTNAME    set the IP address to use for update
    -s, --server=HOST|ADDR     set the dyndns server address that contains
                                the zone to update
Options :
    -u, --username=NAME    username to use for http authentication
    -p, --password=PASS    password to use for http authentication
    --port=PORT            port to use to send get query to server
                            (Default """ + str(self.port) + """)
    --api=URL              url to which send http query parameters
                            (Default '""" + self.url + """')
    --help               display this help message
    --no-output          disable all output message
    -v, --verbose        show more running messages
    -V, --version        print the version
DynDNS protocol features :
    --backmx       set backupmx option YES (Default: """ + self.__fields['backmx'] + """)
    --no-backmx    set backupmx option NO (Default: """ + self.__fields['backmx'] + """)
    --offline      set dyndns to offline mode (Default: """ + self.__fields['offline'] + """)
    --static       set static dns system (Default system : """ + self.__fields['system'] + """)
    --wildcard     set wildcard ON (Default: """ + self.__fields['wildcard'] + """)
    --no-wildcard  set wildcard OFF (Default: """ + self.__fields['wildcard'] + """)
    --url=         set dyndns url feature

Return code :
    0 Success
    1 Other errors during running
    2 Bad argument
    3 Missing required argument
    10 Error during HTTP query
    11 Authentification needed
""")

  def __parseCmdLineOptions(self, options_list):
    """Parse input main options, and apply rules

    @param[dict] options_list : array of option key => value
    """
    for opt in options_list:
      if opt[0] in ['-a', '--address']:
        address = opt[1].strip()
        match = self.__re_ip.match(address)
        if match:
          self.__fields['myip'] = match.group('ipv4')
        else:
          self.__logger.error('bad ip address given ' + address)
          sys.exit(2)
      if opt[0] in ['-h', '--hostname']:
        self.__fields['hostname'] = opt[1]
      if opt[0] in ['-u', '--username']:
        self.username = opt[1]
      if opt[0] in ['-p', '--password']:
        self.password = opt[1]
      if opt[0] in ['-s', '--server']:
        self.server = opt[1]
      if opt[0] == '--port':
        self.port = int(opt[1])
      if opt[0] == '--api':
        self.url = opt[1]

      if opt[0] in ['-v', '--verbose']:
        self.__logger.setLevel('DEBUG')
      if opt[0] == '--no-output':
        # disable logging
        logging.disable(logging.CRITICAL + 1)

      if opt[0] == '--backmx':
        self.__fields['backmx'] = 'YES'
      if opt[0] == '--no-backmx':
        self.__fields['backmx'] = 'NO'
      if opt[0] == '--offline':
        self.__fields['offline'] = 'YES'
      if opt[0] == '--static':
        self.__fields['system'] = 'statdns'
      if opt[0] == '--wildcard':
        self.__fields['wildcard'] = 'YES'
      if opt[0] == '--no-wildcard':
        self.__fields['wildcard'] = 'NO'
      if opt[0] == '--url':
        self.__fields['url'] = opt[1]

      if opt[0] == '--help':
        self.showUsage()
        sys.exit(0)
      if opt[0] in ['-V', '--version']:
        DynUpdate.showVersion()
        sys.exit(0)

  def start(self, argv):
    """Entry point of the launcher

    @param[dict] argv : array of shell options given by main function
    """
    # read the only allowed command line options
    try:
      short_opts = 'a:h:u:p:s:vV'
      long_opts = ['address=',
                   'hostname=',
                   'username=', 'password=',
                   'server=', 'port=',
                   'api=',
                   'no-output', 'verbose',
                   'backmx', 'no-backmx', 'offline', 'static',
                   'wildcard', 'no-wildcard', 'url=',
                   'help', 'version']
      options_list, args = getopt.getopt(argv[1:], short_opts, long_opts)
    except getopt.GetoptError as e:
      self.__logger.error(e)
      self.showUsage()
      return 2
    except Exception as e:
      self.__logger.error('Problem during parameters interpretation :')
      self.__logger.error('   ' + str(e))
      return 1

    self.__parseCmdLineOptions(options_list)

    for val in [self.server,
                self.__fields['myip'],
                self.__fields['hostname'],
                ]:
      if not val:
        self.__logger.error('Missing a required argument use --help')
        return 3
    self.__logger.debug('debug: config fields ' + str(self.__fields))
    return self.query()

  def query(self):
    """Forge and send the HTTP GET query

    @return[integer] : True if query success
                      False otherwise
    """
    # bulding url
    # remove trailing slash to be sure to add only one slash at the beginning of
    # the url
    url = '/' + self.url.strip('/') + '?'

    # fill the url parameters with all DYNdns options
    for param in self.__fields:
      if not url.endswith('?'):
        url += '&'
      url += param + '=' + self.__fields[param]
    # /bulding url

    self.__logger.debug('url set to : "' + url + '"')

    # instanciate the connection
    conn = HTTPConnection(self.server, self.port, timeout=2)
    self.__logger.debug('query to : ' + self.server +
                        ':' + str(self.port))

    # init the dict header
    headers = {'User-Agent': 'dyn-update/' + version}

    # handle authentification
    if self.username and self.password:
      self.__logger.debug('authentication enable')
      # build the auth string
      auth_str = self.username + ':' + self.password
      # encode it as a base64 string to put in http header
      auth = b64encode(auth_str.encode()).decode("ascii")
      # fill the header
      headers['Authorization'] = 'Basic ' + auth
    else:
      self.__logger.debug('authentication disable')

    try:
      # exec the query
      conn.request('GET', url, headers=headers)
      res = conn.getresponse()
      data = res.read().decode()
      conn.close()
    except socket.gaierror as e:
      self.__logger.debug('unable to resolve hostname ' + str(e))
      return 10
    except socket.error as e:
      self.__logger.debug('unable to connect to host ' + str(e))
      return 10

    self.__logger.debug('HTTP status ' + str(res.status) + ' ' + res.reason)
    self.__logger.debug('HTTP data "' + data + '"')
    if res.status == 401:
      self.__logger.error('the server require an authentification')
      return 11
    elif res.status == 200:
      self.__logger.info('Success')
      return 0


##
# Run launcher as the main program
if __name__ == '__main__':
  launcher = DynUpdate()
  sys.exit(launcher.start(sys.argv))
