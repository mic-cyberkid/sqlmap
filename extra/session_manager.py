#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json
import re
import threading

from lib.core.common import getSafeExString
from lib.core.common import parseJson
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.settings import UNICODE_ENCODING
class SessionManager(object):
    """
    Handles automated session management and authentication flows.
    """

    def __init__(self):
        self.token = None
        self.lock = threading.Lock()
        self.in_refresh = False

    def get_or_refresh_auth_token(self, force=False):
        """
        Retrieves the current auth token or fetches a new one if expired/forced.
        """
        if not conf.authUrl:
            return None

        with self.lock:
            if self.token and not force:
                return self.token

            if self.in_refresh:
                return self.token

            logger.info("retrieving authentication token from '%s'" % conf.authUrl)

            try:
                self.in_refresh = True
                from lib.request.connect import Connect as Request
                # We use Request.getPage directly to avoid recursion or interference
                # with the main injection flow.
                page, headers, code = Request.getPage(
                    url=conf.authUrl,
                    post=conf.authData,
                    method=HTTPMETHOD.POST,
                    direct=True,
                    silent=True
                )

                if page:
                    deserialized = parseJson(page)
                    if deserialized:
                        from thirdparty.jsonpath_ng import parse as parse_jsonpath
                        try:
                            jsonpath_expr = parse_jsonpath(conf.authKeyPath)
                            matches = jsonpath_expr.find(deserialized)
                            if matches:
                                self.token = str(matches[0].value)
                                logger.info("successfully retrieved auth token: %s" % self.token)
                                return self.token
                        except Exception as ex:
                            logger.error("failed to parse auth token from response: %s" % getSafeExString(ex))

                logger.error("failed to retrieve auth token (code: %s)" % code)

            except Exception as ex:
                logger.error("error during auth token retrieval: %s" % getSafeExString(ex))
            finally:
                self.in_refresh = False

        return self.token

    def inject_auth_into_request(self, request):
        """
        Modifies the request object to include the current auth token.
        Currently supports replacing "SESSION" placeholder in body/url/headers.
        """
        token = self.get_or_refresh_auth_token()
        if not token:
            return request

        # Replace placeholder in URL
        if "SESSION" in request.get_full_url():
            request._Request__url = request.get_full_url().replace("SESSION", token)

        # Replace placeholder in body
        if request.data and b"SESSION" in request.data:
            request.data = request.data.replace(b"SESSION", token.encode(UNICODE_ENCODING))

        # Replace placeholder in headers
        for key, value in list(request.headers.items()):
            if "SESSION" in str(value):
                request.headers[key] = value.replace("SESSION", token)

        return request

    def check_expiration(self, page):
        """
        Checks if the response indicates session expiration.
        """
        if not conf.authExpireString or not page:
            return False

        expired = False
        if conf.authExpireString.startswith("/") and conf.authExpireString.endswith("/"):
            pattern = conf.authExpireString[1:-1]
            if re.search(pattern, page, re.I):
                expired = True
        elif conf.authExpireString in page:
            expired = True

        if expired:
            logger.warning("session expiration detected, refreshing token")
            self.get_or_refresh_auth_token(force=True)
            return True

        return False

session_manager = SessionManager()
