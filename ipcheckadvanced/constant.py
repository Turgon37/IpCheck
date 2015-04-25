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

This file contains all Event constant. Use these keyword\n
to give event code and event type
"""

__all__ = ['E_BEFORE_CHECK', 'E_AFTER_CHECK',
           'E_START', 'E_UPDATE', 'E_NOUPDATE',
           'E_ERROR',
           'T_NORMAL', 'T_CUSTOM',
           'T_ERROR_FILE', 'T_ERROR_NOIP', 'T_ERROR_PERMS', 'T_ERROR_EXTENSION']

# Here are the event enumeration
E_BEFORE_CHECK = 1
E_AFTER_CHECK = 3

E_START = 10
E_UPDATE = 11
E_NOUPDATE = 12

E_ERROR = 20

# here are the event type enumeration
T_NORMAL = 50
T_ERROR_NOIP = 51  # unable to retrieve ip from internet
T_ERROR_FILE = 52  # unable to read previous ip from local file
T_ERROR_PERMS = 53  # unable to properly access to file system
T_ERROR_EXTENSION = 54  # error occurs during extension execution
T_CUSTOM = 60   # custom error the data dict must contain the 'msg' key
