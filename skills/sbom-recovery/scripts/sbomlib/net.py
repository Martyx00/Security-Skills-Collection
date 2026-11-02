"""The only real ``Http`` implementation (contract sections 0 G8 and 3.11): HTTPS GET of JSON through ``urllib``.

``urllib`` honours the proxy environment variables on its own. Only ``https://`` URLs are fetched and redirects are
followed only to ``https://``. HTTP errors are returned as responses; every transport failure (DNS, connect, TLS, proxy
CONNECT, timeout) is ``errors.NetworkUnavailable``. Header values (the NVD ``apiKey``) are never logged or put into an
exception message.
"""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from sbomlib import errors
from sbomlib.context import Http, HttpResponse

MAX_BODY_BYTES = 16 * 1024 * 1024


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        if not newurl.lower().startswith("https://"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _parse_body(data: bytes) -> Optional[Any]:
    if not data or len(data) > MAX_BODY_BYTES:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _lower_headers(headers: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for key, value in headers.items():
            out[str(key).lower()] = str(value)
    except AttributeError:
        pass
    return out


class UrllibHttp(Http):
    def __init__(self, user_agent: str = "kiro-sbomber") -> None:
        self.user_agent = user_agent

    def get_json(self, url: str, headers: Dict[str, str], timeout: float) -> HttpResponse:
        if not isinstance(url, str) or not url.lower().startswith("https://"):
            raise errors.NetworkUnavailable("only https:// URLs are fetched")
        merged = {"User-Agent": self.user_agent, "Accept": "application/json"}
        merged.update(headers or {})
        request = urllib.request.Request(url, headers=merged, method="GET")
        opener = urllib.request.build_opener(_HttpsOnlyRedirect)
        try:
            with opener.open(request, timeout=timeout) as response:
                status = int(response.status)
                data = response.read(MAX_BODY_BYTES + 1)
                reply_headers = _lower_headers(response.headers)
        except urllib.error.HTTPError as exc:
            try:
                data = exc.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException):
                data = b""
            return HttpResponse(int(exc.code), _parse_body(data), _lower_headers(exc.headers))
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, http.client.HTTPException,
                OSError) as exc:
            raise errors.NetworkUnavailable("the request failed: %s" % type(exc).__name__) from exc
        return HttpResponse(status, _parse_body(data), reply_headers)
