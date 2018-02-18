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

"""IpCheck - Constant file

This file contains all Event constant.
Use these keyword to give event code and event type
"""

# Here are the event enumeration
g_cstt_event = [
    'E_BEFORE_CHECK',  # empty event raised before update
    'E_AFTER_CHECK',  # empty event raised after update
    'E_START',  # it's the first time the script is run, no previous ip
    'E_UPDATE',  # the Ip address value have changed from last check
    'E_NOUPDATE',  # the ip address is the same as from last check
    'E_ERROR'  # an error appear see type for detail
]
# here are the ERROR type enumeration
g_cstt_type = [
    'T_NORMAL',  # no error
    'T_CUSTOM',  # custom error must be described in the 'msg' data
    'T_ERROR_NOIP_URLS',  # unable to retrieve ip from internet
    'T_ERROR_NOIP_FILE',  # unable to read previous ip from local file
    'T_ERROR_FILE',  # unable to properly access to file system
    'T_ERROR_EXTENSION'  # error occurs during extension execution
]

__all__ = g_cstt_event + g_cstt_type

# Load each constant with a incremented integer because we don't care about values
cstt_value = 1
for cstt in __all__:
    globals()[cstt] = cstt_value
    cstt_value += 1
del cstt_value
