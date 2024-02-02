#!/usr/bin/env python3
"""Defines authentication class"""
from flask import request
from typing import List, TypeVar


class Auth():
    """authentication class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require authorithation"""
        return False

    def authorization_header(self, request=None) -> str:
        """authorization header"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current user"""
        return None
