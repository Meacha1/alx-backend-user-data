#!/usr/bin/env python3
"""Module for implementing basic authentication for the API
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User

class CustomBasicAuth(Auth):
    """Custom basic authentication class.
    """
    def extract_b64_auth_header_part(
            self,
            auth_header: str) -> str:
        """Extracts the Base64 part from the Authorization header
        for basic authentication.
        """
        if type(auth_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field_match = re.fullmatch(pattern, auth_header.strip())
            if field_match is not None:
                return field_match.group('token')
        return None

    def decode_b64_auth_header(
            self,
            b64_auth_header: str,
            ) -> str:
        """Decodes a base64-encoded authorization header.
        """
        if type(b64_auth_header) == str:
            try:
                decoded_res = base64.b64decode(
                    b64_auth_header,
                    validate=True,
                )
                return decoded_res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_credentials(
            self,
            decoded_b64_auth_header: str,
            ) -> Tuple[str, str]:
        """Extracts user credentials from a base64-decoded authorization
        header using the basic authentication method.
        """
        if type(decoded_b64_auth_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                pattern,
                decoded_b64_auth_header.strip(),
            )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None

    def user_from_credentials(
            self,
            email: str,
            pwd: str) -> TypeVar('User'):
        """Retrieves a user based on their authentication credentials.
        """
        if type(email) == str and type(pwd) == str:
            try:
                users = User.search({'email': email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(pwd):
                return users[0]
        return None

    def get_current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the user from a request.
        """
        auth_hdr = self.authorization_header(request)
        b64_hdr_part = self.extract_b64_auth_header_part(auth_hdr)
        decoded_auth_hdr = self.decode_b64_auth_header(b64_hdr_part)
        user_email, user_pwd = self.extract_credentials(decoded_auth_hdr)
        return self.user_from_credentials(user_email, user_pwd)
