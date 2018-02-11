#!/usr/bin/env python3
# -*- coding: utf8 -*-

# This file is a part of ipcheck
#
# Copyright (c) 2015-2018 Pierre GINDRAUD
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
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO event SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Main IpCheck class
"""

# System imports
from base64 import b64encode
import argparse
import http.client
import logging
import os
import re
import socket
import ssl
import subprocess
import sys

# python 3
if sys.version_info[0] == 3:
    string_types = str,
else:
    string_types = basestring,

# Projet Import
# Try to import from current directory
try:
    import ipcheckadvanced
except ImportError:
    try:
        sys.path.insert(1, "/usr/share")
        import ipcheckadvanced
    except ImportError as e:
        ipcheckadvanced = None
        print(e, file=sys.stderr)

if ipcheckadvanced is not None:
    import types
    from ipcheckadvanced import IpCheckLoader
    from ipcheckadvanced.constant import *

# Global project declarations
__version__ = '3.0.0'


class IpCheck:
    """Ipcheck program
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

    RE_URL = re.compile(REG_E_URL)
    RE_IP = re.compile(REG_E_IP)


    def __init__(self):
        """Constructor : Build an ipcheck object
        """
        # list of urls from which retrieve urls
        self.__urls = dict({4: dict(), 6: dict()})
        # disable ssl certificate verification False by default
        self.__tls_insecure = False
        # The HTTP timeout
        self.__timeout = 5
        # directory in which to store the local file
        self.__tmp_directory = '/var/tmp/'
        # the command to run after ip updating
        self.__command = None
        # ip version number for which to try to retrieve ip address
        self.__ip_versions = [4]
        # the file
        self.__file_pattern = 'ipv{ip_version}'

        # init logger
        self.__logger = logging.getLogger('ipcheck')
        self.__logger.setLevel(logging.DEBUG)
        out_formatter = logging.Formatter("[%(name)s] %(levelname)s : %(message)s")
        # register stdout handler
        self.__logger_stdout = logging.StreamHandler(sys.stdout)
        self.__logger_stdout.setFormatter(out_formatter)
        self.__logger_stdout.setLevel(logging.INFO)
        self.__logger.addHandler(self.__logger_stdout)
        # register stderr handler
        self.__logger_stderr = logging.StreamHandler(sys.stderr)
        self.__logger_stderr.setFormatter(out_formatter)
        self.__logger_stderr.setLevel(logging.CRITICAL+1)
        self.__logger.addHandler(self.__logger_stderr)
        # init advanced interface
        self.loader = None
        if ipcheckadvanced is not None and isinstance(ipcheckadvanced, types.ModuleType):
            self.loader = ipcheckadvanced.IpCheckLoader(self.__logger)

    def configure(self, **options):
        """Parse input main program options (restrict to program strict execution)

        @param[dict] options : array of option key => value
        """
        if 'verbose' in options:
            if options['verbose'] < 0:
                self.__logger_stdout.setLevel(logging.CRITICAL + 1)
            else:
                self.__logger_stdout.setLevel(logging.INFO - options['verbose']*10)
        self.__logger.debug('configured with args %s', options)
        if 'errors_to_stderr' in options and options['errors_to_stderr']:
            self.__logger_stderr.setLevel(logging.ERROR)
        # disable SSL certificate verification
        if 'tls_insecure' in options and options['tls_insecure']:
            self.__tls_insecure = True
        # set post update command
        if 'command' in options and options['command']:
            self.__command = options['command']
        # set tmp_directory
        if 'tmp_directory' in options and options['tmp_directory']:
            self.__tmp_directory = options['tmp_directory']
        if 'file_pattern' in options and options['file_pattern']:
            self.__file_pattern = options['file_pattern']
        # add urls to check
        for ip_version in self.__ip_versions:
            key = 'urls_v'+str(ip_version)
            if key in options and options[key]:
                if isinstance(options[key], string_types):
                    options[key] = [options[key]]
                for url in options[key]:
                    self.addUrl(url, ip_version)

        if self.loader:
            # send configuration
            if self.loader.configure(options):
                # initialise python loader
                self.__logger.debug('fetch urls from config file')
                for url in self.loader.getAdditionnalsUrls():
                    self.addUrl(url)
            else:
                self.__logger.debug('unable to load advanced ' +
                                  'IPCheck features module')

    def start(self):
        """Entry point of the program
        """
        for ip_version in self.__ip_versions:
            if len(self.__urls[ip_version]) == 0:
                self.__logger.critical('No configured url for IPv%d version', ip_version)
                return 3

        # check local file system working elements
        if not os.path.isdir(self.__tmp_directory):
            try:
                os.mkdir(self.__tmp_directory)
            except:
                self.__logger.error('Unable to create the required directory %s', self.__tmp_directory)
                return 2
        return self.update() != 0

    def addUrl(self, url, ip_version=4):
        """Entry point for push url to available url list

        @param[string] url : the string that correspond to an entire url
                                    a list of string that describe several urls
        @return[integer] : True if add success
                          False url format error
        """
        # remove trailing white space
        url = url.strip()
        match = self.RE_URL.match(url)
        if match is None:
            self.__logger.error('Invalid url "' + url + '"')
            return False

        d = match.groupdict()
        if url not in self.__urls[ip_version]:
            self.__urls[ip_version][url] = d
            self.__logger.debug('add url : ' + str(d))
        return True

    def update(self):
        """Retrieve the current ip address and compare it to previous one

        This function retrieve the current ip(s)
        @return[boolean] The update status
                          True if update have been performed
                          False if not
        """
        # store return error number
        ret = 0
        if ipcheckadvanced is not None:
            # @event : BEFORE_CHECK
            self.sendEvent(E_BEFORE_CHECK, T_NORMAL)

        # lookup for ip version
        for version in self.__ip_versions:
            # RETRIEVING IP
            current_ip = self.retrieveIp(protocol_version=version)
            if current_ip is None:
                self.__logger.error('Unable to get current IPv%d address', version)
                ret += 1
                if ipcheckadvanced is not None:
                    # @event : ERROR_NOIP = no ip found
                    self.sendEvent(E_ERROR, T_ERROR_NOIP, {
                        'version_ip': version,
                    })
                continue

            path = os.path.join(self.__tmp_directory, self.__file_pattern.format(ip_version=version))
            # FILE EXIST + READABLE => check file and compare previous address
            if os.path.isfile(path) and os.access(path, os.R_OK):
                previous_ip = self.readFromFile(path, version)

                # error in temporary file
                if previous_ip is None:
                    self.__logger.warn('incorrect address read from local file')
                    if ipcheckadvanced is not None:
                        # @event : ERROR_FILE = bad ip from local file
                        self.sendEvent(E_ERROR, T_ERROR_FILE, {
                            'version_ip': version,
                            'file': path,
                        })
                    # IF FILE WRITABLE
                    if os.access(path, os.W_OK):
                        self.__logger.debug('writing directly the current IPv%d address', version)
                        self.writeToFile(current_ip, path)
                    else:
                        self.__logger.error('unsufficient permissions on file system')
                        ret += 1
                        if ipcheckadvanced is not None:
                            # @event : ERROR_FILE = bad ip from local file
                            self.sendEvent(E_ERROR, T_ERROR_PERMS, {
                                'version_ip': version,
                                'file': path,
                            })
                    continue

                # IPS MATCH
                if current_ip == previous_ip:
                    self.__logger.info('IPv%d unchanged', version)
                    if ipcheckadvanced is not None:
                        # @event : NOUPDATE
                        self.sendEvent(E_NOUPDATE, T_NORMAL, {
                            'version_ip': version,
                            'current_ip': current_ip,
                            'previous_ip': previous_ip,
                        })
                # IPS MISMATCH
                else:
                    self.writeToFile(current_ip, path)
                    self.__logger.info('New IPv%d %s', version, current_ip)
                    # call user defined command
                    self.callCommand()
                    if ipcheckadvanced is not None:
                        # @event : UPDATE
                        self.sendEvent(E_UPDATE, T_NORMAL, {
                            'version_ip': version,
                            'current_ip': current_ip,
                            'previous_ip': previous_ip,
                        })

            # FILE NOT EXIST + DIRECTORY WRITABLE =>
            #                        just create file and write address into
            elif not os.path.isfile(path) and os.access(self.__tmp_directory, os.W_OK):
                self.writeToFile(current_ip, path)
                self.__logger.info('Starting with IPv%d %s', version, current_ip)
                # call user defined command
                self.callCommand()
                if ipcheckadvanced is not None:
                    # @event : START
                    self.sendEvent(E_START, T_NORMAL, {
                        'version_ip': version,
                        'current_ip': current_ip,
                    })
            # NO SUFFICIENT PERMISSIONS
            else:
                self.__logger.error('unsufficient permissions on file system')
                ret += 1
                if ipcheckadvanced is not None:
                    # @event : ERROR = read/write right
                    self.sendEvent(E_ERROR, T_ERROR_PERMS, {
                        'version_ip': version,
                        'file': path,
                    })
                continue

        if ipcheckadvanced is not None:
            # @event : AFTER CHECK
            self.sendEvent(E_AFTER_CHECK, T_NORMAL, {
                'status': ret == 0,
            })
        return ret

    def retrieveIp(self, protocol_version=4):
        """Execute the HTTP[S] query to retrieve IP address

        This function make a query for each url registered
        It will stop at the first url for which the query success
        @param protocol_version [int] : the ip version
        @return [str] : The ip address string if found
               [None]  if no address match
        """
        for url in self.__urls[protocol_version]:
            self.__logger.debug('query url %s', url)
            url_parts = self.__urls[protocol_version][url]
            host = url_parts['host']
            port = None
            if url_parts['port']:
                port = url_parts['port']

            # PROTOCOL
            if not url_parts['proto'] or url_parts['proto'] == 'http':
                self.__logger.debug('  -> protocol HTTP')
                if port is None:
                    port = http.client.HTTP_PORT
                conn = http.client.HTTPConnection(host, port, timeout=self._timeout)
            elif url_parts['proto'] == 'https':
                self.__logger.debug('  -> protocol HTTPs')
                if port is None:
                    port = http.client.HTTPS_PORT
                if self.__tls_insecure:
                    context = ssl._create_unverified_context()
                    self.__logger.debug('  -> SSL certificate verification is DISABLED')
                else:
                    context = None
                conn = http.client.HTTPSConnection(host, port,
                                               timeout=self.__timeout,
                                               context=context)
            else:
                self.__logger.error('Found unmanaged url protocol : "%s" ignoring url', url_parts['proto'])
                continue
            # /PROTOCOL

            # HEADER
            # build the header dict
            headers = {'User-Agent': 'ipcheck/' + __version__}
            # authentification
            if url_parts['user'] and url_parts['pass']:
                self.__logger.debug('  -> authentication enable')
                # build the auth string
                auth_str = url_parts['user'] + ':' + url_parts['pass']
                # encode it as a base64 string to put in http header
                auth = b64encode(auth_str.encode()).decode("ascii")
                # fill the header
                headers['Authorization'] = 'Basic ' + auth
            # /HEADER

            # URL
            url = url_parts['path']
            if url_parts['query']:
                url += url_parts['query']
            # /URL

            try:
                conn.request('GET', url, headers=headers)
                res = conn.getresponse()
                data = res.read().decode()
                conn.close()
            except socket.gaierror as e:
                self.__logger.debug('  => unable to resolve hostname %s', str(e))
                continue
            except ssl.SSLError as e:
                self.__logger.debug('  => unable to validate the host\'s certifcate.' +
                                ' You can override this by using --insecure')
                continue
            except socket.error as e:
                self.__logger.debug('  => unable to connect to host %s', str(e))
                continue
            except http.client.HTTPException:
                self.__logger.debug('  => error with HTTP query')
                continue
            except Exception as e:
                self.__logger.error('Unhandled python exception please inform the developper %s', str(e))
                continue

            if res.status == 401:
                self.__logger.debug('  => the server may require an authentification')
                continue

            # lookup for ip matching
            match = self.RE_IP.search(data)
            if match:
                ip = match.group('ipv' + str(protocol_version))
                self.__logger.debug('  => get IPv%d address %s', protocol_version, ip)
                return ip
        self.__logger.error('Cannot obtains current address from any of the given urls')
        return None

    def writeToFile(self, ip, path):
        """Write content (address) to the specified file

        @param content [str] : the content to write in the file
        @param file [str] : the file path
        @return [bool] True if write success
                        False otherwise
        """
        try:
            with open(path, 'w') as f:
                f.write(ip)
        except IOError as e:
            self.__logger.error('Error happened during writing ip to file : %s', str(e))
            return False
        self.__logger.debug('wrote ip address %s to %s', ip, path)
        return True

    def readFromFile(self, path, protocol_version=4):
        """Read the content of specified file and search for ip address

        @param file [str] : the file path
        @param vers [int] : the ip version
        @return [str] The address string
               [None]    if no address can be found
        """
        try:
            with open(path, 'r') as f:
                # read more at 45 bytes (caracters) from file because
                # ipv6 take more at 45 byte to be ascii encoded
                data = f.read(45)
        except IOError as e:
            self.__logger.error(str(e))
            return None
        # check read ip format
        match = self.RE_IP.search(data)
        if match:
            ip = match.group('ipv' + str(protocol_version))
            self.__logger.debug('read ip address %s from %s', ip, path)
            return ip
        return None

    def callCommand(self):
        """Call the given command

        This function call the command given by parameter (if available)
        """
        if self.__command:
            self.__logger.debug('call user command `%s`', str(self.__command))
            if subprocess.call(self.command, timeout=10) == 0:
                self.__logger.info('User\'s command has return success')
            else:
                self.__logger.warning('User\'s command has returned non-zero value')

    def sendEvent(self, event, type, data=dict()):
        """Build a new event and call associated action

        @param event [int] : the event type
        @param type [int] : the event code
        @param data [dict] OPTIONNAL : an optionnal dictionnary which contain
                some value that will be given to handler objects
        """
        # if avanced feature available push new event
        if self.loader is not None:
            self.loader.pushEvent(event, type, data)


# Run launcher as the main program
if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                        argument_default=argparse.SUPPRESS,
                                        description='IpCheck version v' + __version__ + """
This script retrieve the external (public) ip address and take it up-to-date
in a local file""")
    parser.add_argument('-c', '--command', action='store', dest='command',
                            help="""The command to run after the address has been updated.
                            You can put some argument (like --xx) by
                            placing the all CMD into a quoted string""")
    parser.add_argument('-d', '--tmp-directory', action='store', dest='tmp_directory',
                            help='The path of directory into the which all temporary file will be put')
    parser.add_argument('--file-pattern', action='store', dest='file_pattern',
                            help='The filename pattern use to create temporary files with current ips')
    parser.add_argument('-t', '--timeout', action='store', dest='timeout', default=5,
                            help='The HTTP timeout in seconds for all requests')
    parser.add_argument('--no-ssl-cert', '--insecure', action='store', dest='tls_insecure', default=False,
                            help='Disable TLS certificate verification')
    parser.add_argument('-u', '-u4', '--url', '--url-v4', action='append', dest='urls_v4',
                            help='Add url to list of external ip sources')
    parser.add_argument('-u6', '--url-v6', action='append', dest='urls_v6',
                            help='Add url to list of external ip sources')
    logging_group = parser.add_mutually_exclusive_group()
    logging_group.add_argument('--no-output', action='store_const', dest='verbose', const=-1,
                            help='Disable all output message to stdout. (cron mode)')
    logging_group.add_argument('-v', '--verbose', action='count', dest='verbose',
                            help='Show more running messages')
    parser.add_argument('--errors-to-stderr', action='store_true', dest='errors_to_stderr',
                            help='Copy errors to stderr')
    parser.add_argument('-V', '--version', action='store_true', dest='show_version', default=False,
                            help='Print the version and exit')
    # Load advanced parameters
    if ipcheckadvanced is not None:
        ipcheckadvanced.configureArgParser(parser)
    args = parser.parse_args()

    if args.show_version:
        print("IpCheck version v" + __version__)
        sys.exit(0)

    program = IpCheck()
    program.configure(**vars(args))
    sys.exit(program.start())

# Return code :
#     0 Success
#     1 Other errors during running
#     2 Bad argument
#     3 Missing required argument""")
