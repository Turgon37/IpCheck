# -*- coding: utf8 -*-

import http.client
import io
from unittest.mock import Mock


def __mockConnection(connection_mock, response_data='', response_status=200):
    # http response mock
    response_mock = Mock(spec=http.client.HTTPResponse)
    response_mock.read = io.BytesIO(response_data.encode()).read
    response_mock.status = response_status

    # connectionmock
    connection_mock.getresponse.return_value = response_mock

    # class mock
    class_mock = Mock()
    class_mock.return_value = connection_mock

    return class_mock

def createHTTPConnectionMock(*args, **params):
    """Create a mock of the HTTPConnection class
    """
    return __mockConnection(Mock(spec=http.client.HTTPConnection), *args, **params)


def createHTTPSConnectionMock(*args, **params):
    """Create a mock of the HTTPSConnection class
    """
    return __mockConnection(Mock(spec=http.client.HTTPSConnection), *args, **params)
