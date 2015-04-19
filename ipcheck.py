#!/usr/bin/python3
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

"""Main IpCheck class
"""

# System imports
from base64 import b64encode
import getopt
import http.client
import logging
import os
import re
import socket
import ssl
import subprocess
import sys

# Projet Import
# Try to import from current directory
try:
  import ipcheckadvanced
except ImportError:
  try:
    sys.path.insert(1, "/usr/share")
    import ipcheckadvanced
  except ImportError:
    ipcheckadvanced = None

# Global project declarations
version = '1.0.0'


class IpCheck:
  """Build a ip check instance for an unique query
  """
  # define the http protocol string
  REG_E_PROTO = 'https?'

  # match an auth string
  REG_E_AUTH = '(?P<user>[a-zA-Z0-9]+)(?P<pass>:[a-zA-Z0-9]+)?@'

  # match a exact ipv4 address
  REG_E_IPV4 = '(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])'

  # according to RFC 1123 define an hostname
  REG_E_HOST = '(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])'

  # match the exact value of a port number
  REG_E_PORT = '(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'

  # match a resource's path
  REG_E_PATH = '/(?:(?:[a-zA-Z0-9-_~.%]+/?)*)?'

  # match some http parameters
  REG_E_QUERY = '\?(?:&?[a-zA-Z0-9-_~.%]+=?[a-zA-Z0-9-_~.%]*)+'

  # an URL is defined by :
  # PROTO+AUTH+IP|HOST+PORT+PATH+QUERY
  REG_E_URL = ('^(?P<url>(?:(?P<proto>' + REG_E_PROTO + ')://)?' +  # HTTP
               '(?:' + REG_E_AUTH + ')?' +  # USER PASS
               '(?P<host>' + REG_E_IPV4 + '|' + REG_E_HOST + ')' +  # HOST or IP
               '(?P<port>:' + REG_E_PORT + ')?' +  # PORT
               '(?P<path>' + REG_E_PATH + ')' +  # PATH
               '(?P<query>' + REG_E_QUERY + ')?' +  # QUERY
               ')$')

  # an ip address is version 4
  REG_E_IP = '(?P<ipv4>' + REG_E_IPV4 + ')'  # IP matching

  def __init__(self):
    """Constructor : Build an ipcheck object
    """
    # config parser
    # list of urls from which retrieve urls
    self.urls = dict()
    # disable ssl certificate verification False by default
    self.__unsecure_ssl = False
    # directory in which to store the local file
    self.directory = '/var/tmp/'
    # ip version number for which to try to retrieve ip address
    self.ip_version = [4]
    self.ip_prefix = 'ipv'
    # the command to run after ip updating
    self.command = None
    # re object for url parsing
    self.__re_url = re.compile(self.REG_E_URL)
    self.__re_ip = re.compile(self.REG_E_IP)
    # init logger
    self.__logger = logging.getLogger('ipcheck')
    self.__logger.setLevel('INFO')
    hdlr = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(levelname)s : %(message)s")
    hdlr.setFormatter(formatter)
    self.__logger.addHandler(hdlr)

  @staticmethod
  def showVersion():
    """Print the program version
    """
    print("Ip Check version v" + version)

  def showUsage(self):
    """Prints command line options
    """
    print('Usage: ' + sys.argv[0] + ' [OPTIONS...]')
    print("""
Ip Check script v""" + version + """
This script retrieve the external (public) ip address and take it up-to-date
in a local file

Options :
    -c CMD, --command=CMD  the command to run after the address has been
                            updated. You can put some argument (like --xx) by
                            placing the all CMD into a quoted string
    -d PATH, --directory=PATH   the path of directory into the which all
                                temporary file will be putted (Default : '""" +
          self.directory + """')
    --prefix=PRE     set the prefix for local ip storage file (Default : '""" +
          self.ip_prefix + """')
    --no-ssl-cert    disable SSL certificate verification (Default : """ +
          str(self.__unsecure_ssl) + """)
    -u URL, --url=URL    add url to available urls set for querying ip address
    -h, --help       display this help message
    --no-output      disable all output message
    -v, --verbose    show more running messages
    -V, --version    print the version

Return code :
    0 Success
    1 Other errors during running
    2 Bad argument
    3 Missing required argument
""")

  def __parseCmdLineOptions(self, options_list):
    """Parse input main program options (restrict to program strict execution)

    @param[dict] options_list : array of option key => value
    """
    for opt in options_list:
      if opt[0] in ['-v', '--verbose']:
        self.__logger.setLevel('DEBUG')
      if opt[0] == '--no-output':
        # disable logging
        logging.disable(logging.CRITICAL + 1)
      if opt[0] in ['-h', '--help']:
        self.showUsage()
        sys.exit(0)
      if opt[0] in ['-V', '--version']:
        IpCheck.showVersion()
        sys.exit(0)

  def __parseCmdLineArgument(self, options_list):
    """Parse input main required argument, and exec statement

    These options are specific to this program's doing
    @param[dict] options_list : array of option key => value
    """
    for opt in options_list:
      if opt[0] == '--no-ssl-cert':
        # disable SSL certificate verification
        self.__unsecure_ssl = True
      if opt[0] in ['-c', '--command']:
        self.command = opt[1].lstrip('=').split()
      if opt[0] in ['-d', '--directory']:
        self.directory = opt[1].lstrip('=')
      if opt[0] == '--prefix':
        self.ip_prefix = opt[1].lstrip('=').strip()
      if opt[0] in ['-u', '--url']:
        for url in opt[1].lstrip('=').split(','):
          self.addUrl(url)

  def start(self, argv):
    """Entry point of the launcher

    @param[dict] argv : array of shell options given by main function
    """
    # read the only allowed command line options
    try:
      short_opts = 'hVvu:d:c:'
      long_opts = ['help', 'version',
                   'verbose', 'no-output',
                   'url=', 'directory=', 'prefix=', 'command=',
                   'no-ssl-cert']
      options_list, args = getopt.getopt(argv[1:], short_opts, long_opts)
    except getopt.GetoptError as e:
      self.__logger.error(e)
      self.showUsage()
      return 2

    # retrieve optionnal parameter from cmd line
    self.__parseCmdLineOptions(options_list)

    # check if the advanced feature are available
    if ipcheckadvanced is not None:
      import types
      # LOAD ADVANCED FEATURES
      if isinstance(ipcheckadvanced, types.ModuleType):
        self.__logger.debug('enable advanced ipcheck features module')

    # retrieve required arguments from cmd line
    # THESE SETTING OVERRIDE OTHER PREVIOUS SETTING
    self.__parseCmdLineArgument(options_list)

    if len(self.urls) == 0:
      self.__logger.error('No configured url')
      return 3

    # check local file system working elements
    if not os.path.isdir(self.directory):
      self.__logger.error('Invalid directory ' + self.directory)
      return 2
    return self.update() != 0

  def addUrl(self, url):
    """Entry point for push url to available url list

    @param[string] url : the string that correspond to entire url
    @return[integer] : True if add success
                      False url format error
    """
    if not isinstance(url, str):
      return False
    # remove trailing white space
    url = url.strip()
    match = self.__re_url.match(url)
    if match is None:
      self.__logger.error('Invalid url "' + url + '"')
      return False

    d = match.groupdict()
    if url not in self.urls:
      self.urls[url] = d
      self.__logger.debug('add url : ' + str(d))
      return True
    return False

  def update(self):
    """Retrieve the current ip adress and make some update

    This function proceed in a ip lookup then it compare
    the stored value (if available)
    @return[boolean] The update status
                      True if update have been performed
                      False if not
    """
    # store return error number
    ret = 0
    # lookup for ip version
    for vers in self.ip_version:
      # @EVENT : BEFORE CHECK
      current_ip = self.retrieveIp(vers=vers)
      if current_ip is None:
        # @EVENT : ERROR = no ip found
        ret += 1
        continue
      path = self.directory + self.ip_prefix + str(vers)
      # EXIST + READABLE => check file and compare previous address
      if os.path.isfile(path) and os.access(path, os.R_OK):
        previous_ip = self.readFromFile(path, vers)
        if previous_ip is None:
          # @EVENT : ERROR = bad ip from local file
          self.__logger.warn('incorrect address read from local file')
          self.writeToFile(current_ip, path)
        if current_ip == previous_ip:
          # @EVENT : NO UPDATE
          self.__logger.info('IPv' + str(vers) + ' unchanged')
        else:
          # @EVENT : UPDATE
          self.writeToFile(current_ip, path)
          self.__logger.info('New IPv' + str(vers) + ' ' + current_ip)
          # call user defined command
          self.makeCall()
      # NOT EXIST + WRITABLE => just create file and write address into
      elif os.access(self.directory, os.W_OK):
        # @EVENT : START CHECKING
        self.writeToFile(current_ip, path)
        self.__logger.info('Starting IPv' + str(vers) + ' ' + current_ip)
        # call user defined command
        self.makeCall()
      else:
        # @EVENT : ERROR = read/write right
        self.__logger.error('unsufficient permissions on file system')
        ret += 1
        continue
      # @EVENT : AFTER CHECK
    return ret

  def retrieveIp(self, vers=4):
    """Execute the HTTP[S] query to retrieve IP address

    This function make a query for each url registered
    It will stop at the first url for which the query success
    @param[integer] vers : the ip version
    @return[string] : The ip address string if found
            None  if no address match
    """
    for key in self.urls:
      self.__logger.debug('USE ' + key)
      fields = self.urls[key]
      host = fields['host']
      port = None
      if fields['port']:
        port = fields['port']

      # PROTOCOL
      if not fields['proto'] or fields['proto'] == 'http':
        self.__logger.debug('     -> protocol http')
        if port is None:
          port = http.client.HTTP_PORT
        conn = http.client.HTTPConnection(host, port, timeout=2)
      elif fields['proto'] == 'https':
        self.__logger.debug('     -> protocol secure http')
        if port is None:
          port = http.client.HTTPS_PORT
        if self.__unsecure_ssl:
          context = ssl._create_unverified_context()
          self.__logger.debug('     -> SSL certificate check is DISABLED')
        else:
          context = None
        conn = http.client.HTTPSConnection(host, port,
                                           timeout=2,
                                           context=context)
      else:
        self.__logger.debug('     -> unmanaged protocol : ' +
                            fields['proto'])
        continue
      # /PROTOCOL

      # HEADER
      # build the header dict
      headers = {'User-Agent': 'ipcheck/' + version}
      # authentification
      if fields['user'] and fields['pass']:
        self.__logger.debug('     -> authentication enable')
        # build the auth string
        auth_str = fields['user'] + ':' + fields['pass']
        # encode it as a base64 string to put in http header
        auth = b64encode(auth_str.encode()).decode("ascii")
        # fill the header
        headers['Authorization'] = 'Basic ' + auth
      # /HEADER

      # URL
      url = fields['path']
      if fields['query']:
        url += fields['query']
      # /URL

      try:
        conn.request('GET', url, headers=headers)
        res = conn.getresponse()
        data = res.read().decode()
        conn.close()
      except socket.gaierror as e:
        self.__logger.debug('     => unable to resolve hostname ' + str(e))
        continue
      except ssl.SSLError as e:
        self.__logger.debug('     => unable to confirm the host certifcate ' +
                            'to override this please use --no-ssl-cert')
        continue
      except socket.error as e:
        self.__logger.debug('     => unable to connect to host ' + str(e))
        continue

      if res.status == 401:
        self.__logger.debug('     => the server require an authentification')
        continue

      # lookup for ip matching
      st = self.__re_ip.search(data)
      if st:
        self.__logger.debug('     => get ip address ' +
                            st.group('ipv' + str(vers)))
        return st.group('ipv' + str(vers))
    self.__logger.critical('Cannot obtains current address from any of' +
                           ' the given urls')
    return None

  def writeToFile(self, content, file):
    """Write content (address) to the specified file

    @param[string] content : the content to write in the file
    @param[string] file : the file path
    @return[boolean] True if write success
                    False otherwise
    """
    try:
      f = open(file, 'w')
      f.write(content + '\n')
      f.close()
    except IOError:
      self.__logger.critical(str(e))
      return False
    return True

  def readFromFile(self, file, vers=4):
    """Read the content of specified file and search for ip address

    @param[string] file : the file path
    @param[integer] vers : the ip version
    @return[string] The address string
           [None]    if no address can be found
    """
    try:
      f = open(file, 'r')
      # read more at 45 bytes (caracters) from file because
      # ipv6 take more at 45 byte to be ascii encoded
      data = f.read(45)
      f.close()
    except IOError as e:
      self.__logger.error(str(e))
      return None
    # check read ip format
    st = self.__re_ip.search(data)
    if st:
      self.__logger.debug('read ip address ' + st.group('ipv' + str(vers)))
      return st.group('ipv' + str(vers))

  def makeCall(self):
    """Call the given command

    This function call the command given by parameter (if available)
    """
    if self.command:
      self.__logger.debug('call user command `' + str(self.command) + '`')
      if subprocess.call(self.command, timeout=10) == 0:
        self.__logger.debug('command has return success')
      else:
        self.__logger.warning('command has return non-zero value')


# Run launcher as the main program
if __name__ == '__main__':
  launcher = IpCheck()
  sys.exit(launcher.start(sys.argv))
