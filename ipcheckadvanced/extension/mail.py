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
from email.mime.text import MIMEText
import smtplib
from socket import error as socket_error
import socket


# Projet Imports
from . import ExtensionBase
from ..constant import *

"""This extension provide a mail sending on IpCheck Events

The configuration take theses options :
  sender : the name/address of sender field into each mails
  recipient : the mail address to which each mail will be supplied
      (multiple mail allowed separated by colon ',')
  tag : a string to put into bracket in the mail subject.
      This help you to identify a mail among several other
  body : The template of the mail content. This string use string format
      tags. For example theses tag must be put into embrace to be replaced
      by dynamic content during execution :
      {message} will be replaced by a description of the recently happend event
  server : the smtp server hostname
  port : the smtp server port
  auth : a boolean indicates if the smtp need authentication or not.
      If set to True the two next parameters must be filled
  username : the smtp login username
  password : the smtp login password
  start_tls : a boolean that indicates to use or not STARTTLS
  ssl : a boolean that describe the SSL status
  info_mail : a boolean that indicates if the informations mails must be send
"""


class Extension(ExtensionBase):
  """A simple mail trigger which send a mail to someone
  """

  def __init__(self):
    """Default constructor:
    """
    ExtensionBase.__init__(self)

  def load(self):
    """Load the mail trigger with configuration

    @return[boolean] :  True if load success
                        False otherwise
    """
    config = self._config
    if 'sender' not in config or 'recipient' not in config:
      if self._logger:
        self._logger.error('Need a mail sender and recipient')
      return False

    if 'start_tls' not in config:
      config['start_tls'] = false

    # check username and password
    if 'auth' in config:
      if config['auth'] in self.BOOL_TRUE_MAP:
        if 'username' not in config:
          self._logger.error('Need a username for auth')
          return False
        if 'password' not in config:
          self._logger.error('Need a password for auth')
          return False
    else:
      config['auth'] = false

    # check tag for mail subject
    if 'tag' not in config:
      config['tag'] = 'IPCHECK'
    else:
      config['tag'] = config['tag'].strip('[]')

    # check default body
    if 'body' not in config:
      self._logger.error('Need a valid body for mail content')
      return False

    #
    if 'info_mail' in config:
      if config['info_mail'] in self.BOOL_TRUE_MAP:
        config['info_mail'] = True
      else:
        config['info_mail'] = False
    else:
      config['info_mail'] = False

    return True

  def handle(self, event, type, data):
    """Receive all event from main class

    @return[boolean] :  True if handle success
                        False otherwise
    """
    conf = self._config
    subject = '[' + socket.gethostname() + '][' + conf['tag'] + '] '
    message = None

    if 'version_ip' in data:
      version = 'v' + data['version_ip']
    else:
      version = ''

    # Apply event type
    if event == E_UPDATE and conf['info_mail'] == True:
      # IP was updated
      subject += 'Updating IP' + version
      message = ('The IP' + version + ' address associated to the host <' +
                 socket.getfqdn() + '> have been updated to (' +
                 data['current_ip'] + ')')
    elif event == E_START and conf['info_mail'] == True:
      # IP checking system was started
      subject += 'Starting IP' + version
      message = ('The IP' + version + ' address associated to the host <' +
                 socket.getfqdn() + '> have been set to (' +
                 data['current_ip'] + ')')
    elif event == E_ERROR:
      # IP checker has encounter an error
      if type == T_ERROR_FILE:
        subject += 'Error with file'
        message = ('The IP' + version + ' address read from local file "' +
                   data['file'] + '" is incorrect')
      elif type == T_ERROR_PERMS:
        subject += 'Error with permissions'
        message = ('There is an error with filesystem permission on file "' +
                   data['file'] + '".\nPlease check this problem quickly,' +
                   ' this application may be broken.')
      elif type == T_CUSTOM:
        subject += 'Error ' + data['subject']
        message = data['msg']
      else:
        self._logger.error('No mail message configured for this ERROR.' +
                           'Please contact administrator')

    if message is not None:
      body = conf['body'].replace('\\n', '\n').format(message=message)
      return self.sendmail(subject, body)
    return True

  def sendmail(self, subject, body):
    """Sendmail function

    @param[string] subject : the mail subject
    @param[string] body : the entire body of the mail
    """
    conf = self._config
    try:
      if conf['ssl'] in self.BOOL_TRUE_MAP:
        conn = smtplib.SMTP_SSL(host=conf['server'],
                                port=conf['port'],
                                timeout=1)
      else:
        conn = smtplib.SMTP(host=conf['server'],
                            port=conf['port'],
                            timeout=1)
    except socket_error as e:
      if self._logger:
        self._logger.error('Unable to connect to ' +
                           conf['server'] + ':' + conf['port'])
      return False

    if conf['start_tls'] in self.BOOL_TRUE_MAP:
      conn.starttls()
    if conf['auth'] in self.BOOL_TRUE_MAP:
      conn.login(conf['username'], conf['password'])

    # Building mail
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = conf['sender']
    msg['To'] = conf['recipient']
    self._logger.info('Send mail to "' + conf['recipient'] + '"')
    conn.sendmail(conf['sender'],
                  conf['recipient'].split(','),
                  msg.as_string())
    conn.quit()
    return True
