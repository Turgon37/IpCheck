# -*- coding: utf8 -*-

import io
from unittest.mock import Mock


class ConnexionMock(object):
    """This mock the http.client class"""

    def __init__(self, response_data='', response_status=200):
        # Methods
        self.request = Mock()
        self.close = Mock()

        self.response_data = io.BytesIO(response_data.encode())
        self.response_status = response_status

    def getresponse(self):
        mocked_response = Mock()
        mocked_response.read = self.response_data.read
        mocked_response.status = Mock(return_value=self.response_status)
        return mocked_response
