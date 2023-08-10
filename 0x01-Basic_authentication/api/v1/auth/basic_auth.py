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
    
    def decode_base64_authorization_header(authorization_header: str) -> str:
        '''Returns the decoded value of a Base64 string'''
        if authorization_header is None or not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return base64.b64decode(authorization_header[6:]).decode('utf-8')
    

    def extract_base64_authorization_header(authorization_header: str) -> str:
        '''Returns the Base64 part of the Authorization header'''
        if authorization_header is None or not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header[6:]
    

    def extract_user_credentials(decoded_base64_authorization_header: str) -> Tuple[str, str]:
        '''Returns the user email and password from the Base64 decoded value'''
        if decoded_base64_authorization_header is None or not isinstance(decoded_base64_authorization_header, str) or ':' not in decoded_base64_authorization_header:
            return None, None
        return tuple(decoded_base64_authorization_header.split(':', 1))
