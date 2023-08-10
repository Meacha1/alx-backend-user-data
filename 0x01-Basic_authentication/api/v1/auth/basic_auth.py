#!/usr/bin/env python3
'''Basic authentication module'''
import base64
import binascii
import re
from typing import Tuple, TypeVar
from .auth import Auth


class BasicAuth(Auth):
    '''Basic authentication class'''
    def __init__(self, *args: str, **kwargs: str) -> None:
        '''Constructor'''
        super().__init__(*args, **kwargs)

    def _decode(self, encoded_string: str) -> Tuple[str, str]:
        '''Decodes a base64 string'''
        try:
            decoded_string = base64.b64decode(encoded_string).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return None, None
        return re.split(':', decoded_string, 1)

    def _validate(self, user: str, password: str) -> bool:
        '''Validates a user and password'''
        return user == self.user and password == self.password

    def _authenticate(self, header: str) -> bool:
        '''Authenticates a request'''
        if not header:
            return False
        if not header.startswith('Basic '):
            return False
        user, password = self._decode(header[6:])
        if not user or not password:
            return False
