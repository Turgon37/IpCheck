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

    def getDefaultConfig(self):
        """Return the default configuration items for this extension
        """
        return super(Extension, self).getDefaultConfig({
            'auth': False,
            'info_mail': True,
            'server': 'localhost',
            'port': 25,
            'ssl': False,
            'start_tls': False,
            'tag': 'IPCHECK',
            'subject': '[{hostname}][{tag}] ',
            'subject_on_start': 'Starting IPv{version_ip}',
            'message_on_start': ('The IPv{version_ip} address associated to the host ' +
                '<{hostname_fqdn}> have been set to {current_ip}'),
            'subject_on_update': 'Updating IPv{version_ip}',
            'message_on_update': ('The IPv{version_ip} address associated to the host ' +
                '<{hostname_fqdn}> have been updated to {current_ip}'),
            'subject_on_error_file': 'Error with temporary file',
            'message_on_error_file': ('The IPv{version_ip} address read from local file "' +
                '{file}" is incorrect'),
            'subject_on_error_perms': 'Error with permissions',
            'message_on_error_perms': ('There is an error with filesystem permission on file "' +
                '{file}".\nPlease check this problem quickly, this application may be broken.'),
            'subject_on_error_extension': 'Error with an extension',
            'message_on_error_extension': ('There is an error with extension "{extension}".' +
                '\nThis message will inform you about the detail of the error :\n{msg}' +
                '\nPlease check this problem quickly, this application may be broken.'),
            'subject_on_error_custom': 'Error {subject}',
            'message_on_error_custom': '{msg}',
        })

    def load(self):
        """Load the mail trigger with configuration

        @return [bool] :  True if load success
                            False otherwise
        """
        config = self.getDefaultConfig()
        config.update(self.configuration)
        if 'sender' not in config or 'recipient' not in config:
            self.logger.error('Need a mail sender and recipient')
            return False

        # check username and password
        if 'auth' in config and Extension.isTrue(config['auth']):
            if 'username' not in config:
                self.logger.error('Need a username for auth')
                return False
            if 'password' not in config:
                self.logger.error('Need a password for auth')
                return False

        # check default body
        if 'body' not in config:
            self.logger.error('Need a valid body for mail content')
            return False

        if 'info_mail' in config:
            if Extension.isTrue(config['info_mail']):
                self.logger.debug('info mail enabled')
                config['info_mail'] = True
            else:
                self.logger.debug('info mail disabled')
                config['info_mail'] = False

        self.configuration = config
        return True

    def handle(self, event, type, data):
        """Receive all event from main class

        @return[boolean] :  True if handle success
                            False otherwise
        """
        conf = self.configuration
        key = None

        # Apply event type
        if event == E_UPDATE and conf['info_mail']:
            # IP was updated
            key = 'on_update'
        elif event == E_START and conf['info_mail']:
            # IP checking system was started
            key = 'on_start'
        elif event == E_ERROR:
            # IP checker has encounter an error
            if type == T_ERROR_FILE:
                key = 'on_error_file'
            elif type == T_ERROR_PERMS:
                key = 'on_error_perms'
            elif type == T_ERROR_EXTENSION:
                key = 'on_error_extension'
            elif type == T_CUSTOM:
                key = 'on_error_extension'
            else:
                self.logger.error('No mail message configured for this ERROR.' +
                                ' Please contact developper')
                return False
        else:
            self.logger.debug('No mail configured to catch this event')
            return True

        data.update(conf)
        subject = (conf.get('subject') + conf.get('subject_'+key))
        body = conf['body'].replace('\\n', '\n')
        try:
            subject = subject.format(**data)
            message = conf.get('message_'+key).format(**data)
            body = body.format(message=message, **data).format(**data)
        except KeyError as e:
            self.logger.error('One of your template use a variable that is ' +
                                'not available in this context : %s', str(e))
        return self.sendmail(subject, body)

    def sendmail(self, subject, body):
        """Sendmail function

        @param[string] subject : the mail subject
        @param[string] body : the entire body of the mail
        """
        conf = self.configuration
        try:
            if conf['ssl']:
                conn = smtplib.SMTP_SSL(host=conf['server'],
                                        port=conf['port'],
                                        timeout=1)
            else:
                conn = smtplib.SMTP(host=conf['server'],
                                    port=conf['port'],
                                    timeout=1)
        except socket_error as e:
            self.logger.error('Unable to connect to %s:%s',
                                    str(conf['server']), str(conf['port']))
            return False

        if conf['start_tls']:
            conn.starttls()
        if conf['auth']:
            conn.login(conf['username'], conf['password'])

        # Building mail
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = conf['sender']
        msg['To'] = conf['recipient']
        self.logger.info('Send mail to "' + conf['recipient'] + '"')
        conn.sendmail(conf['sender'],
                    conf['recipient'].split(','),
                    msg.as_string())
        conn.quit()
        return True
