#!/usr/bin/env python3
"""Defines authentication class"""
from flask import request
from typing import List, TypeVar


class Auth():
    """authentication class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require authorithation"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != '/':
            path += '/'
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """authorization header"""
        if not request:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """current user"""
        return None
