#!/usr/bin/env python3
'''Authentication module'''
from flask import request
from typing import List, TypeVar
import re


class Auth:
    '''Auth class'''
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''Require auth method'''
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path += '/'
        for i in excluded_paths:
            if i[-1] == '*':
                if i[:-1] in path:
                    return False
            elif i == path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        '''Authorization header method'''
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        '''Current user method'''
        return None

    def session_cookie(self, request=None):
        '''Session cookie method'''
        if request is None:
            return None
        return request.cookies.get('session_id')
