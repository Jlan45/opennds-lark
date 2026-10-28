#!/usr/bin/env python3
# Copyright (C) 2026 the opennds-lark contributors
# Based on the openNDS FAS examples,
# Copyright (C) Blue Wave Projects and Services 2015-2026
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
"""Feishu/Lark one-time-code Forward Authentication Service for openNDS.

This is a standalone FAS for fas_secure_enabled level 1 (the same base64
query used by fas-hid.php). It does not replace ThemeSpec. openNDS redirects
a captive client here with a base64 "fas" blob. The client names a Feishu
identity, this process sends a short-lived code through the bot IM API, and
after the code matches it serves the standard auth form:

    http://<gatewayaddress>/<authdir>/?tok=<sha256(hid + faskey)>&redir=...&custom=...

openNDS accepts that tok only when it equals sha256(client.hid + faskey),
which is what fas-hid.php computes with PHP hash('sha256', hid.key) and what
the daemon computes with sha256sum. Level 2/3 (AES) and level 4 (https +
authmon) are intentionally not implemented.

Secrets are read from the environment or from the file named by
FAS_LARK_ENV_FILE. Nothing in this file is a credential.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("fas_lark")

API_HOSTS = frozenset({"open.feishu.cn", "open.larksuite.com"})
TOKEN_RETRY_CODES = frozenset({99991661, 99991663, 99991664, 99991668})
ID_TYPES = ("email", "mobile", "open_id", "user_id", "union_id")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
OPEN_ID_RE = re.compile(r"^ou_[A-Za-z0-9]{4,64}$")
UNION_ID_RE = re.compile(r"^on_[A-Za-z0-9]{4,64}$")
USER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+\-]{0,63}$")
HID_RE = re.compile(r"^[0-9a-fA-F]{64}$")
MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
AUTHDIR_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_FAS_LEN = 12000
MAX_BODY = 16384

FAS_FIELD_ORDER = (
    "hid",
    "clientip",
    "clientmac",
    "client_type",
    "cpi_query",
    "gatewayname",
    "gatewayurl",
    "version",
    "gatewayaddress",
    "gatewaymac",
    "originurl",
    "clientif",
    "themespec",
)


class ConfigError(Exception):
    """The process cannot start with the current settings."""


class PortalError(Exception):
    """A failure that can be shown on the portal page."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class FeishuError(Exception):
    """The bot API did not accept the call."""

    def __init__(self, message: str, *, code: int | None = None, public: str | None = None):
        super().__init__(message)
        self.code = code
        self.public = public or message


def auth_token(hid: str, faskey: str) -> str:
    """Return the openNDS level-1 tok, sha256(hid + faskey) as lowercase hex."""

    return hashlib.sha256((hid + faskey).encode("utf-8")).hexdigest()


def build_fas_blob(fields: dict) -> str:
    """Encode a level-1 fas blob the way openNDS does (comma-space, standard base64)."""

    ordered = []
    seen = set()
    for key in FAS_FIELD_ORDER:
        if key in fields:
            ordered.append(f"{key}={fields[key]}")
            seen.add(key)
    for key, value in fields.items():
        if key not in seen:
            ordered.append(f"{key}={value}")
    raw = ", ".join(ordered)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def demo_fas_blob(
    hid: str | None = None,
    gatewayaddress: str = "192.168.1.1:2050",
    clientmac: str = "aa:bb:cc:dd:ee:ff",
    clientip: str = "10.0.0.8",
    gatewayname: str = "openNDS",
) -> str:
    """Build a portal blob for a dry-run page check.

    The hid is random unless supplied. openNDS will reject the resulting tok
    unless this hid belongs to a live client, so the blob cannot authorize
    a real session by itself.
    """

    if hid is None:
        hid = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    if not HID_RE.fullmatch(hid):
        raise ConfigError("demo hid must be 64 hex characters")
    if not valid_gateway_address(gatewayaddress):
        raise ConfigError("demo gateway address is invalid")
    return build_fas_blob(
        {
            "hid": hid,
            "clientip": clientip,
            "clientmac": clientmac,
            "client_type": "cpd_can",
            "cpi_query": "",
            "gatewayname": urllib.parse.quote(gatewayname, safe=""),
            "gatewayurl": urllib.parse.quote("http://status.client", safe=""),
            "version": "fas-lark",
            "gatewayaddress": gatewayaddress,
            "gatewaymac": "00:11:22:33:44:55",
            "originurl": urllib.parse.quote("http://example.com/", safe=""),
            "clientif": "br-lan",
            "themespec": "",
        }
    )


def parse_fas_blob(blob: str) -> dict:
    if not blob or len(blob) > MAX_FAS_LEN:
        raise PortalError(
            "门户参数不完整或已损坏，请断开 Wi-Fi 后重新连接。"
            " The portal parameters are missing or invalid. Reconnect to Wi-Fi."
        )
    raw = blob.strip().replace(" ", "+")
    try:
        padded = raw + ("=" * ((4 - len(raw) % 4) % 4))
        decoded = base64.b64decode(padded, validate=False).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise PortalError(
            "门户参数不完整或已损坏，请断开 Wi-Fi 后重新连接。"
            " The portal parameters are missing or invalid. Reconnect to Wi-Fi."
        ) from exc
    if len(decoded) > MAX_FAS_LEN:
        raise PortalError(
            "门户参数不完整或已损坏，请断开 Wi-Fi 后重新连接。"
            " The portal parameters are missing or invalid. Reconnect to Wi-Fi."
        )
    fields = {}
    for part in decoded.split(", "):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        if key and key not in fields:
            fields[key] = value
    return fields


def valid_gateway_address(value: str) -> bool:
    if not value or len(value) > 128 or any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return False
    if value.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:(\d{1,5})", value)
        if not match:
            return False
        try:
            ipaddress.IPv6Address(match.group(1))
        except ValueError:
            return False
        port = int(match.group(2))
        return 1 <= port <= 65535
    match = re.fullmatch(r"([A-Za-z0-9._-]+):(\d{1,5})", value)
    if not match:
        return False
    host, port = match.group(1), int(match.group(2))
    if not 1 <= port <= 65535 or host.startswith(".") or host.endswith(".") or ".." in host:
        return False
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
    return True


def normalize_api_base(value: str) -> str:
    raw = (value or "https://open.feishu.cn").strip().rstrip("/")
    parts = urllib.parse.urlsplit(raw)
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in ("",)
        or parts.port not in (None, 443)
        or host not in API_HOSTS
    ):
        raise ConfigError(
            "FEISHU_API_BASE must be https://open.feishu.cn (Feishu) "
            "or https://open.larksuite.com (international Lark)"
        )
    return f"https://{host}"


def normalize_identity(id_type: str, raw: str) -> str:
    if id_type not in ID_TYPES:
        raise PortalError("请选择飞书身份类型。 Choose a Feishu/Lark identity type.")
    value = (raw or "").strip()
    if id_type == "email":
        value = value.lower()
        if not EMAIL_RE.fullmatch(value) or len(value) > 254:
            raise PortalError("请填写有效的飞书邮箱。 Enter a valid Feishu/Lark email.")
        return value
    if id_type == "mobile":
        return _normalize_mobile(value)
    if id_type == "open_id" and OPEN_ID_RE.fullmatch(value):
        return value
    if id_type == "union_id" and UNION_ID_RE.fullmatch(value):
        return value
    if id_type == "user_id" and USER_ID_RE.fullmatch(value):
        return value
    raise PortalError("请检查飞书邮箱、手机号或 ID 是否填写正确。 Check the Feishu/Lark identity.")


def _normalize_mobile(raw: str) -> str:
    compact = re.sub(r"[\s\-()]", "", raw)
    if compact.startswith("00"):
        compact = "+" + compact[2:]
    if compact.startswith("+"):
        digits = compact[1:]
    elif compact.isdigit() and len(compact) == 11 and compact.startswith("1"):
        return "+86" + compact
    elif compact.isdigit() and len(compact) == 13 and compact.startswith("86"):
        return "+" + compact
    else:
        raise PortalError(
            "手机号请使用国际格式（例如 +8613800138000）。大陆 11 位号码会自动补 +86。"
            " Use an international number such as +8613800138000."
        )
    if not digits.isdigit() or not 8 <= len(digits) <= 15:
        raise PortalError(
            "手机号请使用国际格式（例如 +8613800138000）。"
            " Use an international number such as +8613800138000."
        )
    return "+" + digits


def mask_identity(id_type: str, value: str) -> str:
    if id_type == "email" and "@" in value:
        local, domain = value.split("@", 1)
        head = local[:1]
        return f"{head}***@{domain}"
    if id_type == "mobile" and len(value) > 7:
        return value[:4] + "****" + value[-4:]
    if len(value) > 8:
        return value[:4] + "***" + value[-2:]
    return "***"


def display_text(value: str, limit: int = 80) -> str:
    text = urllib.parse.unquote(value or "")
    cleaned = "".join(ch for ch in text if ch.isprintable() and ch not in "<>")
    return cleaned[:limit] or "openNDS"


def custom_b64(id_type: str, id_value: str) -> str:
    plain = f"feishu_id_type={id_type}, feishu_id={id_value}"
    return base64.b64encode(plain.encode("utf-8")).decode("ascii")


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def read_env_file(path: str) -> dict:
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as exc:
        raise ConfigError(f"cannot read FAS_LARK_ENV_FILE {path}: {exc}") from exc
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not ENV_KEY_RE.fullmatch(key):
            raise ConfigError(f"invalid environment name in {path}")
        values[key] = value
    return values


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _bounded_int(mapping: dict, name: str, default: int, low: int, high: int) -> int:
    raw = (mapping.get(name) or "").strip()
    if not raw:
        return default
    try:
        number = int(raw, 10)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not low <= number <= high:
        raise ConfigError(f"{name} must be between {low} and {high}")
    return number


class Config:
    def __init__(
        self,
        *,
        app_id: str,
        app_secret: str,
        verification_token: str,
        encrypt_key: str,
        api_base: str,
        faskey: str,
        authdir: str,
        listen: str,
        port: int,
        ttl: int,
        otp_length: int,
        max_attempts: int,
        resend_seconds: int,
        max_sends_per_ip: int,
        max_sends_per_id: int,
        store_path: str,
        dry_run: bool,
        resolve_email: bool,
        public_host: str,
        gateway_pin: str,
        http_timeout: float,
    ):
        self.app_id = app_id
        self.app_secret = app_secret
        self.verification_token = verification_token
        self.encrypt_key = encrypt_key
        self.api_base = api_base
        self.faskey = faskey
        self.authdir = authdir
        self.listen = listen
        self.port = port
        self.ttl = ttl
        self.otp_length = otp_length
        self.max_attempts = max_attempts
        self.resend_seconds = resend_seconds
        self.max_sends_per_ip = max_sends_per_ip
        self.max_sends_per_id = max_sends_per_id
        self.store_path = store_path
        self.dry_run = dry_run
        self.resolve_email = resolve_email
        self.public_host = public_host
        self.gateway_pin = gateway_pin
        self.http_timeout = http_timeout

    @property
    def credentials_configured(self) -> bool:
        return bool(self.app_id and self.app_secret)

    @classmethod
    def from_env(cls, environ: dict | None = None) -> "Config":
        source = os.environ if environ is None else environ
        data = dict(source)
        path = (data.get("FAS_LARK_ENV_FILE") or "").strip()
        if path:
            for key, value in read_env_file(path).items():
                data.setdefault(key, value)
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, mapping: dict) -> "Config":
        dry_run = _truthy(mapping.get("FEISHU_DRY_RUN"))
        app_id = (mapping.get("FEISHU_APP_ID") or "").strip()
        app_secret = (mapping.get("FEISHU_APP_SECRET") or "").strip()
        verification_token = (mapping.get("FEISHU_VERIFICATION_TOKEN") or "").strip()
        encrypt_key = (mapping.get("FEISHU_ENCRYPT_KEY") or "").strip()
        faskey = (mapping.get("OPENNDS_FASKEY") or "").strip()
        authdir = (mapping.get("OPENNDS_AUTHDIR") or "opennds_auth").strip()
        listen = (mapping.get("FAS_LISTEN") or "0.0.0.0").strip()
        public_host = (mapping.get("FAS_PUBLIC_HOST") or "").strip()
        gateway_pin = (mapping.get("OPENNDS_GATEWAY_ADDRESS") or "").strip()
        store_path = (mapping.get("OTP_STORE_PATH") or "/tmp/opennds-lark/otp.json").strip()

        for label, secret in (
            ("FEISHU_APP_ID", app_id),
            ("FEISHU_APP_SECRET", app_secret),
            ("FEISHU_VERIFICATION_TOKEN", verification_token),
            ("FEISHU_ENCRYPT_KEY", encrypt_key),
            ("OPENNDS_FASKEY", faskey),
        ):
            if secret and re.search(r"[\s\x00-\x1f]", secret):
                raise ConfigError(f"{label} must not contain whitespace or control characters")

        if not re.fullmatch(r"[A-Za-z0-9]{8,256}", faskey):
            raise ConfigError(
                "OPENNDS_FASKEY is required and must be 8-256 letters or digits, "
                "the same value as openNDS option faskey"
            )
        if not AUTHDIR_RE.fullmatch(authdir):
            raise ConfigError("OPENNDS_AUTHDIR must be a short token such as opennds_auth")
        try:
            ipaddress.ip_address(listen)
        except ValueError as exc:
            raise ConfigError("FAS_LISTEN must be an IP address") from exc
        if public_host and not _valid_public_host(public_host):
            raise ConfigError("FAS_PUBLIC_HOST must look like status.client:2080")
        if gateway_pin and not valid_gateway_address(gateway_pin):
            raise ConfigError("OPENNDS_GATEWAY_ADDRESS must look like 192.168.1.1:2050")
        if not dry_run:
            if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", app_id):
                raise ConfigError("FEISHU_APP_ID is required unless FEISHU_DRY_RUN=1")
            if not app_secret or len(app_secret) < 8 or len(app_secret) > 256:
                raise ConfigError("FEISHU_APP_SECRET is required unless FEISHU_DRY_RUN=1")
        elif app_id and not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", app_id):
            raise ConfigError("FEISHU_APP_ID is invalid")
        for label, secret in (
            ("FEISHU_VERIFICATION_TOKEN", verification_token),
            ("FEISHU_ENCRYPT_KEY", encrypt_key),
        ):
            if secret and not 1 <= len(secret) <= 256:
                raise ConfigError(f"{label} must be 1-256 characters")

        port = _bounded_int(mapping, "FAS_PORT", 2080, 1, 65535)
        if port == 80:
            raise ConfigError("FAS_PORT 80 is reserved by openNDS for captive-portal detection")
        return cls(
            app_id=app_id,
            app_secret=app_secret,
            verification_token=verification_token,
            encrypt_key=encrypt_key,
            api_base=normalize_api_base(mapping.get("FEISHU_API_BASE") or ""),
            faskey=faskey,
            authdir=authdir,
            listen=listen,
            port=port,
            ttl=_bounded_int(mapping, "OTP_TTL_SECONDS", 300, 30, 1800),
            otp_length=_bounded_int(mapping, "OTP_LENGTH", 6, 4, 8),
            max_attempts=_bounded_int(mapping, "OTP_MAX_ATTEMPTS", 5, 1, 20),
            resend_seconds=_bounded_int(mapping, "OTP_RESEND_SECONDS", 60, 0, 3600),
            max_sends_per_ip=_bounded_int(mapping, "OTP_MAX_SENDS_PER_IP", 8, 1, 100),
            max_sends_per_id=_bounded_int(mapping, "OTP_MAX_SENDS_PER_ID", 5, 1, 100),
            store_path=store_path,
            dry_run=dry_run,
            resolve_email=_truthy(mapping.get("FEISHU_RESOLVE_EMAIL")),
            public_host=public_host,
            gateway_pin=gateway_pin,
            http_timeout=float(_bounded_int(mapping, "FEISHU_HTTP_TIMEOUT", 8, 3, 30)),
        )


def _valid_public_host(value: str) -> bool:
    if len(value) > 255 or any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return False
    if value.startswith("["):
        return re.fullmatch(r"\[[0-9A-Fa-f:.]+\](?::\d{1,5})?", value) is not None
    return re.fullmatch(r"[A-Za-z0-9._-]{1,253}(?::\d{1,5})?", value) is not None


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FeishuError("Feishu/Lark API redirect was rejected", public=_PUBLIC_UNREACHABLE)


def default_opener():
    # An empty ProxyHandler keeps the app secret on the direct TLS connection.
    opener = urllib.request.build_opener(_RejectRedirect, urllib.request.ProxyHandler({}))
    opener.addheaders = [("User-Agent", "opennds-fas-lark/1.0")]

    def _open(request, timeout):
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            # Feishu reports many API errors as HTTP 400 with a JSON code.
            return exc.code, exc.read()

    return _open


_PUBLIC_UNREACHABLE = "暂时无法连接飞书，请稍后再试。 Feishu/Lark is unreachable."
_PUBLIC_DENIED = "飞书拒绝了发送请求，请联系网络管理员。 The bot was not allowed to send the message."
_PUBLIC_UNKNOWN_USER = (
    "无法向该飞书账号发送验证码。请确认对方属于本企业，且应用可用范围包含该用户。"
    " The bot could not message that account. The person must belong to this tenant "
    "and be inside the app's availability range."
)


class FeishuClient:
    """Tenant-token cache and IM send. `opener(request, timeout)` returns (status, body)."""

    def __init__(self, config: Config, opener=None):
        self.config = config
        self._open = opener or default_opener()
        self._lock = threading.Lock()
        self._token = ""
        self._token_deadline = 0.0

    def send_login_code(self, id_type: str, identifier: str, code: str) -> None:
        minutes = max(1, self.config.ttl // 60)
        text = (
            f"【门户上网验证码】{code}\n"
            f"{minutes} 分钟内有效。如非本人操作请忽略。\n"
            f"Portal code: {code}"
        )
        receive_type, receive_id = self._recipient(id_type, identifier)
        self._send_text(receive_type, receive_id, text)

    def tenant_token(self, force: bool = False) -> str:
        now = time.time()
        with self._lock:
            if not force and self._token and now < self._token_deadline:
                return self._token
        payload = self._request(
            "POST",
            "/open-apis/auth/v3/tenant_access_token/internal",
            {"app_id": self.config.app_id, "app_secret": self.config.app_secret},
            token="",
        )
        token = payload.get("tenant_access_token") or ""
        if not token:
            raise FeishuError("missing tenant_access_token", public=_PUBLIC_DENIED)
        try:
            expire = int(payload.get("expire") or 3600)
        except (TypeError, ValueError):
            expire = 3600
        with self._lock:
            self._token = token
            self._token_deadline = time.time() + max(30, expire - 120)
        return token

    def _recipient(self, id_type: str, identifier: str) -> tuple[str, str]:
        if id_type == "mobile" or (id_type == "email" and self.config.resolve_email):
            open_id = self._lookup_open_id(id_type, identifier)
            return "open_id", open_id
        if id_type == "email":
            return "email", identifier
        return id_type, identifier

    def _lookup_open_id(self, id_type: str, identifier: str) -> str:
        body = {"include_resigned": False}
        if id_type == "mobile":
            body["mobiles"] = [identifier]
        else:
            body["emails"] = [identifier]
        payload = self._authed(
            "POST",
            "/open-apis/contact/v3/users/batch_get_id?user_id_type=open_id",
            body,
        )
        users = ((payload.get("data") or {}).get("user_list") or [])
        for user in users:
            found = user.get("user_id") or ""
            if OPEN_ID_RE.fullmatch(found):
                return found
        raise FeishuError(f"no open_id for {id_type}", code=0, public=_PUBLIC_UNKNOWN_USER)

    def _send_text(self, receive_type: str, receive_id: str, text: str) -> None:
        if receive_type not in {"open_id", "user_id", "union_id", "email"}:
            raise FeishuError("unsupported receive_id_type", public=_PUBLIC_DENIED)
        self._authed(
            "POST",
            "/open-apis/im/v1/messages?receive_id_type=" + receive_type,
            {
                "receive_id": receive_id,
                "msg_type": "text",
                "content": json.dumps({"text": text}, ensure_ascii=False),
            },
        )

    def _authed(self, method: str, path: str, body: dict) -> dict:
        token = self.tenant_token()
        try:
            return self._request(method, path, body, token=token)
        except FeishuError as exc:
            if exc.code not in TOKEN_RETRY_CODES:
                raise
            log.info("refreshing Feishu tenant token after code %s", exc.code)
            token = self.tenant_token(force=True)
            return self._request(method, path, body, token=token)

    def _request(self, method: str, path: str, body: dict | None, token: str) -> dict:
        url = self.config.api_base + path
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            status, raw = self._open(request, timeout=self.config.http_timeout)
        except FeishuError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("Feishu API transport error: %s", exc.__class__.__name__)
            raise FeishuError("transport", public=_PUBLIC_UNREACHABLE) from exc
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            log.warning("Feishu API returned a non-JSON body, HTTP %s", status)
            raise FeishuError("bad json", public=_PUBLIC_UNREACHABLE) from exc
        if not isinstance(payload, dict):
            raise FeishuError("bad payload", public=_PUBLIC_UNREACHABLE)
        code = payload.get("code", 0)
        if code not in (0, None):
            log.warning("Feishu API code %s on %s", code, path.split("?", 1)[0])
            public = _PUBLIC_UNKNOWN_USER if code in {99992360, 230013, 99992351} else _PUBLIC_DENIED
            raise FeishuError(f"api code {code}", code=int(code), public=public)
        return payload


class DryRunFeishu:
    """Stand-in used when FEISHU_DRY_RUN=1. It does not contact Feishu."""

    def __init__(self, config: Config):
        self.config = config

    def send_login_code(self, id_type: str, identifier: str, code: str) -> None:
        log.warning(
            "FEISHU_DRY_RUN accepted a code for %s %s; the code is shown on the portal page",
            id_type,
            mask_identity(id_type, identifier),
        )


class OtpStore:
    """File-backed one-time codes. The plaintext code is never written."""

    def __init__(self, config: Config, now=None):
        self.config = config
        self._now = now or time.time
        self._lock_path = config.store_path + ".lock"
        self._thread = threading.Lock()

    def begin_send(self, peer_ip: str, id_key: str) -> None:
        with self._exclusive():
            state = self._load()
            now = int(self._now())
            self._prune(state, now)
            if not self._allow(state, "ip:" + peer_ip, now, self.config.max_sends_per_ip):
                raise PortalError("发送过于频繁，请稍后再试。 Please wait before requesting another code.")
            if not self._allow(state, "id:" + id_key, now, self.config.max_sends_per_id):
                raise PortalError("这个账号的验证码发送过于频繁，请稍后再试。 Please wait before requesting another code.")
            self._mark(state, "ip:" + peer_ip, now)
            self._mark(state, "id:" + id_key, now)
            self._save(state)

    def save_code(self, hid: str, peer_ip: str, id_type: str, id_value: str, code: str) -> str:
        digest = self._digest(hid, code)
        with self._exclusive():
            state = self._load()
            now = int(self._now())
            self._prune(state, now)
            state["otps"][hid] = {
                "digest": digest,
                "peer_ip": peer_ip,
                "id_type": id_type,
                "id_value": id_value,
                "expires": now + self.config.ttl,
                "attempts": 0,
            }
            self._save(state)
        return digest

    def rollback_code(self, hid: str, digest: str) -> None:
        with self._exclusive():
            state = self._load()
            entry = state["otps"].get(hid)
            if entry and entry.get("digest") == digest:
                del state["otps"][hid]
                self._save(state)

    def verify(self, hid: str, peer_ip: str, id_type: str, id_value: str, code: str) -> str:
        with self._exclusive():
            state = self._load()
            now = int(self._now())
            entry = state["otps"].get(hid)
            if entry and int(entry.get("expires") or 0) <= now:
                del state["otps"][hid]
                self._prune(state, now)
                self._save(state)
                return "expired"
            self._prune(state, now)
            entry = state["otps"].get(hid)
            if not entry:
                self._save(state)
                return "missing"
            if entry.get("peer_ip") != peer_ip:
                return "ip"
            supplied = self._digest(hid, code)
            expected = str(entry.get("digest") or "")
            same_id = entry.get("id_type") == id_type and entry.get("id_value") == id_value
            digest_ok = len(supplied) == len(expected) and hmac.compare_digest(supplied, expected)
            if not same_id or not digest_ok:
                entry["attempts"] = int(entry.get("attempts") or 0) + 1
                if entry["attempts"] >= self.config.max_attempts:
                    del state["otps"][hid]
                    self._save(state)
                    return "locked"
                self._save(state)
                return "wrong"
            del state["otps"][hid]
            self._save(state)
            return "ok"

    def _digest(self, hid: str, code: str) -> str:
        return hmac.new(
            self.config.faskey.encode("utf-8"),
            f"{hid}:{code}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _allow(self, state: dict, key: str, now: int, limit: int) -> bool:
        stamps = [stamp for stamp in state["sends"].get(key, []) if now - stamp < 3600]
        state["sends"][key] = stamps
        if self.config.resend_seconds and stamps and now - stamps[-1] < self.config.resend_seconds:
            return False
        return len(stamps) < limit

    def _mark(self, state: dict, key: str, now: int) -> None:
        stamps = state["sends"].setdefault(key, [])
        stamps.append(now)

    def _prune(self, state: dict, now: int) -> None:
        dead = [hid for hid, entry in state["otps"].items() if int(entry.get("expires") or 0) <= now]
        for hid in dead:
            del state["otps"][hid]
        for key, stamps in list(state["sends"].items()):
            fresh = [stamp for stamp in stamps if now - int(stamp) < 3600]
            if fresh:
                state["sends"][key] = fresh
            else:
                del state["sends"][key]

    def _exclusive(self):
        return _FileLock(self._thread, os.path.dirname(self.config.store_path) or ".", self._lock_path)

    def _load(self) -> dict:
        try:
            with open(self.config.store_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            data = {}
        except (OSError, json.JSONDecodeError):
            log.warning("OTP store was unreadable and will be replaced")
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("otps", {})
        data.setdefault("sends", {})
        if not isinstance(data["otps"], dict):
            data["otps"] = {}
        if not isinstance(data["sends"], dict):
            data["sends"] = {}
        return data

    def _save(self, state: dict) -> None:
        directory = os.path.dirname(self.config.store_path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        fd, tmp = tempfile.mkstemp(prefix="otp-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.config.store_path)
            os.chmod(self.config.store_path, 0o600)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


class _FileLock:
    def __init__(self, thread_lock, directory: str, path: str):
        self._thread_lock = thread_lock
        self._directory = directory
        self._path = path
        self._handle = None

    def __enter__(self):
        self._thread_lock.acquire()
        try:
            os.makedirs(self._directory, mode=0o700, exist_ok=True)
            self._handle = open(self._path, "a+", encoding="utf-8")
            if sys.platform != "win32":
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        except Exception:
            if self._handle is not None:
                self._handle.close()
            self._thread_lock.release()
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._handle is not None and sys.platform != "win32":
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            if self._handle is not None:
                self._handle.close()
            self._thread_lock.release()


class ClientSession:
    def __init__(self, fields: dict, config: Config):
        hid = fields.get("hid", "")
        mac = fields.get("clientmac", "")
        gateway = fields.get("gatewayaddress", "")
        if not HID_RE.fullmatch(hid) or not MAC_RE.fullmatch(mac) or not valid_gateway_address(gateway):
            raise PortalError(
                "门户参数不完整或已损坏，请断开 Wi-Fi 后重新连接。"
                " The portal parameters are missing or invalid. Reconnect to Wi-Fi."
            )
        if config.gateway_pin and gateway != config.gateway_pin:
            raise PortalError(
                "网关地址与 FAS 配置不一致，拒绝授权。"
                " Gateway address does not match this FAS."
            )
        self.hid = hid
        self.mac = mac.lower()
        self.gatewayaddress = gateway
        self.clientip = display_text(fields.get("clientip", ""), 64)
        self.gatewayname = display_text(fields.get("gatewayname", "openNDS"))
        self.clientif = display_text(fields.get("clientif", ""), 64)


def new_code(length: int) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))


class PortalApp:
    def __init__(self, config: Config, feishu=None, store: OtpStore | None = None):
        self.config = config
        self.store = store or OtpStore(config)
        if feishu is not None:
            self.feishu = feishu
        elif config.dry_run:
            self.feishu = DryRunFeishu(config)
        else:
            self.feishu = FeishuClient(config)

    def handle(self, handler: BaseHTTPRequestHandler) -> None:
        try:
            self._dispatch(handler)
        except PortalError as exc:
            _send_html(handler, 200, _page("无法继续", f"<p class=\"err\">{esc(exc.message)}</p>"))
        except Exception:
            log.exception("portal request failed")
            _send_html(
                handler,
                500,
                _page("门户暂时不可用", "<p class=\"err\">门户暂时不可用，请稍后再试。 The portal is temporarily unavailable.</p>"),
            )

    def _dispatch(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urllib.parse.urlparse(handler.path)
        if parsed.path.rstrip("/") == "/health" and handler.command == "GET":
            self._health(handler)
            return
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        form = {}
        if handler.command == "POST":
            form = _read_form(handler)
        elif handler.command != "GET":
            _send_html(handler, 405, _page("不支持的请求", "<p class=\"err\">Method not allowed.</p>"))
            return
        if (query.get("landing") or [""])[0] == "1" or form.get("landing") == ["1"]:
            _send_html(handler, 200, _landing_page())
            return
        if (query.get("status") or [""])[0] == "authenticated":
            _send_html(handler, 200, _already_online_page())
            return
        blob = _first(form, "fas") or _first(query, "fas")
        if blob:
            blob = blob.replace(" ", "+")
        action_path = _safe_path(parsed.path)
        action = _first(form, "action") if handler.command == "POST" else ""
        if action == "request":
            self._request_code(handler, action_path, blob, _first(form, "id_type"), _first(form, "id_value"))
            return
        if action == "verify":
            self._verify_code(
                handler,
                action_path,
                blob,
                _first(form, "id_type"),
                _first(form, "id_value"),
                _first(form, "code"),
            )
            return
        if not blob:
            _send_html(handler, 200, _orphan_page())
            return
        session = ClientSession(parse_fas_blob(blob), self.config)
        _send_html(handler, 200, _identify_page(self.config, session, action_path, blob, "", "", ""))

    def _request_code(self, handler, action_path: str, blob: str, id_type: str, id_value: str) -> None:
        session = ClientSession(parse_fas_blob(blob), self.config)
        try:
            normalized = normalize_identity(id_type, id_value)
        except PortalError as exc:
            _send_html(
                handler,
                200,
                _identify_page(self.config, session, action_path, blob, id_type, id_value, exc.message),
            )
            return
        peer = _peer_ip(handler)
        id_key = id_type + ":" + normalized
        try:
            self.store.begin_send(peer, id_key)
            code = new_code(self.config.otp_length)
            digest = self.store.save_code(session.hid, peer, id_type, normalized, code)
            try:
                self.feishu.send_login_code(id_type, normalized, code)
            except Exception:
                self.store.rollback_code(session.hid, digest)
                raise
        except PortalError as exc:
            _send_html(
                handler,
                200,
                _identify_page(self.config, session, action_path, blob, id_type, id_value, exc.message),
            )
            return
        except FeishuError as exc:
            log.info("Feishu send failed for %s", mask_identity(id_type, normalized))
            _send_html(
                handler,
                200,
                _identify_page(self.config, session, action_path, blob, id_type, id_value, exc.public),
            )
            return
        log.info("sent portal code to %s %s", id_type, mask_identity(id_type, normalized))
        shown = code if self.config.dry_run else ""
        _send_html(
            handler,
            200,
            _verify_page(self.config, session, action_path, blob, id_type, normalized, "", shown),
        )

    def _verify_code(self, handler, action_path: str, blob: str, id_type: str, id_value: str, code: str) -> None:
        session = ClientSession(parse_fas_blob(blob), self.config)
        try:
            normalized = normalize_identity(id_type, id_value)
        except PortalError as exc:
            _send_html(
                handler,
                200,
                _identify_page(self.config, session, action_path, blob, id_type, id_value, exc.message),
            )
            return
        digits = (code or "").strip()
        result = self.store.verify(session.hid, _peer_ip(handler), id_type, normalized, digits)
        messages = {
            "missing": "请先获取验证码。 Request a code first.",
            "expired": "验证码已过期，请重新获取。 The code has expired.",
            "locked": "错误次数过多，请重新获取验证码。 Too many attempts. Request a new code.",
            "wrong": "验证码不正确。 Wrong code.",
            "ip": "请用刚才申请验证码的同一台设备继续。 Continue on the same device that requested the code.",
        }
        if result != "ok":
            page_error = messages.get(result, messages["wrong"])
            if result in {"missing", "expired", "locked"}:
                _send_html(
                    handler,
                    200,
                    _identify_page(self.config, session, action_path, blob, id_type, normalized, page_error),
                )
            else:
                _send_html(
                    handler,
                    200,
                    _verify_page(self.config, session, action_path, blob, id_type, normalized, page_error, ""),
                )
            return
        tok = auth_token(session.hid, self.config.faskey)
        _send_html(handler, 200, _grant_page(self.config, session, tok, id_type, normalized))

    def _health(self, handler) -> None:
        body = json.dumps(
            {
                "ok": True,
                "service": "opennds-fas-lark",
                "api_base": self.config.api_base,
                "dry_run": self.config.dry_run,
                "credentials_configured": self.config.credentials_configured,
                "verification_token_configured": bool(self.config.verification_token),
                "encrypt_key_configured": bool(self.config.encrypt_key),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        handler.wfile.write(body)


def _peer_ip(handler: BaseHTTPRequestHandler) -> str:
    host = handler.client_address[0]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError as exc:
        raise PortalError("无法识别客户端地址。") from exc


def _first(mapping: dict, name: str) -> str:
    values = mapping.get(name) or []
    if not values:
        return ""
    return values[0] if isinstance(values, list) else str(values)


def _read_form(handler: BaseHTTPRequestHandler) -> dict:
    raw_length = handler.headers.get("Content-Length", "")
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise PortalError("请求格式不正确。 Bad request.") from exc
    if length < 0 or length > MAX_BODY:
        raise PortalError("请求过大。 Request is too large.")
    raw = handler.rfile.read(length)
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise PortalError("请求格式不正确。 Bad request.") from exc
    parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
    return {key: values for key, values in parsed.items()}


def _send_html(handler: BaseHTTPRequestHandler, status: int, page: str) -> None:
    body = page.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Connection", "close")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action http: https:; base-uri 'none'",
    )
    handler.end_headers()
    handler.wfile.write(body)


def _page(title: str, inner: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{esc(title)}</title>
<style>
body {{ margin: 0; background: #f4f6f8; color: #1f2329; font-family: sans-serif; }}
main {{ max-width: 28rem; margin: 0 auto; padding: 1.25rem; }}
h1 {{ font-size: 1.35rem; margin: 0 0 0.4rem; }}
label {{ display: block; margin: 0.85rem 0 0.3rem; font-weight: 600; }}
input, select, button {{ width: 100%; font-size: 1rem; padding: 0.7rem; box-sizing: border-box; }}
button {{ background: #3370ff; color: #fff; border: 0; border-radius: 6px; margin-top: 1rem; }}
.err {{ background: #fff2f0; color: #9c2a2a; padding: 0.7rem; border-radius: 6px; }}
.note, .en {{ color: #646a73; font-size: 0.92rem; }}
.banner {{ background: #fff7e8; color: #8a5a00; padding: 0.7rem; border-radius: 6px; }}
code.otp {{ display: block; font-size: 1.6rem; letter-spacing: 0.25rem; margin: 0.6rem 0; }}
</style>
</head>
<body><main>
{inner}
</main></body></html>
"""


def _intro(session: ClientSession) -> str:
    return (
        f"<h1>连接网络</h1>"
        f"<p class=\"en\">Connect to {esc(session.gatewayname)}</p>"
        f"<p class=\"note\">设备 {esc(session.clientip)} · {esc(session.clientif)}</p>"
    )


def _safe_path(path: str) -> str:
    if not path or not re.fullmatch(r"/[A-Za-z0-9/_.-]{0,127}", path) or "//" in path or ".." in path:
        return "/"
    return path


def _identify_page(
    config: Config,
    session: ClientSession,
    action_path: str,
    blob: str,
    id_type: str,
    id_value: str,
    error: str,
) -> str:
    options = []
    for kind, label in (
        ("email", "飞书邮箱 / email"),
        ("mobile", "飞书手机号 / mobile"),
        ("open_id", "open_id"),
        ("user_id", "user_id"),
        ("union_id", "union_id"),
    ):
        selected = " selected" if id_type == kind else ""
        options.append(f"<option value=\"{kind}\"{selected}>{label}</option>")
    error_html = f"<p class=\"err\">{esc(error)}</p>" if error else ""
    return _page(
        "连接网络",
        _intro(session)
        + error_html
        + "<p>验证码会由飞书 / Lark <strong>机器人私聊</strong>发给你，不是短信。"
        + " The code arrives in the bot chat, not by SMS.</p>"
        + f"<form method=\"post\" action=\"{esc(action_path)}\">"
        + f"<input type=\"hidden\" name=\"fas\" value=\"{esc(blob)}\">"
        + "<input type=\"hidden\" name=\"action\" value=\"request\">"
        + "<label for=\"id_type\">飞书身份 / Feishu identity</label>"
        + f"<select id=\"id_type\" name=\"id_type\">{''.join(options)}</select>"
        + "<label for=\"id_value\">邮箱、手机号或 ID</label>"
        + f"<input id=\"id_value\" name=\"id_value\" autocomplete=\"username\" value=\"{esc(id_value)}\" required>"
        + "<button type=\"submit\">获取验证码 / Send code</button>"
        + "</form>"
        + f"<p class=\"note\">验证码 {config.ttl // 60} 分钟内有效，请使用已加入本企业飞书的账号。</p>",
    )


def _verify_page(
    config: Config,
    session: ClientSession,
    action_path: str,
    blob: str,
    id_type: str,
    id_value: str,
    error: str,
    shown: str,
) -> str:
    error_html = f"<p class=\"err\">{esc(error)}</p>" if error else ""
    banner = ""
    if config.dry_run:
        banner = (
            "<p class=\"banner\">演练模式：验证码只显示在本页，没有发给飞书。"
            " Dry-run is on. Turn off FEISHU_DRY_RUN before real use.</p>"
        )
        if shown:
            banner += f"<code class=\"otp\">{esc(shown)}</code>"
    else:
        banner = (
            f"<p>验证码已通过飞书机器人发送，请在 {max(1, config.ttl // 60)} 分钟内输入。"
            " Enter the code sent by the bot.</p>"
        )
    return _page(
        "输入验证码",
        _intro(session)
        + error_html
        + banner
        + f"<p class=\"note\">发给 {esc(mask_identity(id_type, id_value))}</p>"
        + f"<form method=\"post\" action=\"{esc(action_path)}\">"
        + f"<input type=\"hidden\" name=\"fas\" value=\"{esc(blob)}\">"
        + "<input type=\"hidden\" name=\"action\" value=\"verify\">"
        + f"<input type=\"hidden\" name=\"id_type\" value=\"{esc(id_type)}\">"
        + f"<input type=\"hidden\" name=\"id_value\" value=\"{esc(id_value)}\">"
        + "<label for=\"code\">验证码 / One-time code</label>"
        + f"<input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" "
        + f"pattern=\"[0-9]*\" maxlength=\"{config.otp_length}\" required>"
        + "<button type=\"submit\">确认并上网 / Continue</button>"
        + "</form>"
        + f"<form method=\"post\" action=\"{esc(action_path)}\">"
        + f"<input type=\"hidden\" name=\"fas\" value=\"{esc(blob)}\">"
        + "<input type=\"hidden\" name=\"action\" value=\"request\">"
        + f"<input type=\"hidden\" name=\"id_type\" value=\"{esc(id_type)}\">"
        + f"<input type=\"hidden\" name=\"id_value\" value=\"{esc(id_value)}\">"
        + "<button type=\"submit\">重新发送 / Send again</button>"
        + "</form>",
    )


def _grant_page(config: Config, session: ClientSession, tok: str, id_type: str, id_value: str) -> str:
    action = f"http://{session.gatewayaddress}/{config.authdir}/"
    redir = _landing_url(config, session)
    custom = custom_b64(id_type, id_value)
    return _page(
        "验证通过",
        _intro(session)
        + "<p>验证通过。请点击按钮完成上网授权。验证码已失效。"
        + " Code accepted. Use the button to finish sign-in.</p>"
        + f"<form method=\"get\" action=\"{esc(action)}\">"
        + f"<input type=\"hidden\" name=\"tok\" value=\"{esc(tok)}\">"
        + f"<input type=\"hidden\" name=\"custom\" value=\"{esc(custom)}\">"
        + f"<input type=\"hidden\" name=\"redir\" value=\"{esc(redir)}\">"
        + "<button type=\"submit\">开始上网 / Go online</button>"
        + "</form>",
    )


def _landing_url(config: Config, session: ClientSession) -> str:
    if config.public_host:
        return f"http://{config.public_host}/?landing=1"
    return f"http://{session.gatewayaddress}/?landing=1"


def _landing_page() -> str:
    return _page(
        "已经可以上网",
        "<h1>已经可以上网</h1>"
        "<p>授权已提交。如果这个窗口没有自动关闭，现在可以访问互联网。"
        " Access has been granted. You can use the internet if this window stays open.</p>",
    )


def _already_online_page() -> str:
    return _page(
        "已经在线",
        "<h1>这台设备已经可以上网</h1><p>This device is already online.</p>",
    )


def _orphan_page() -> str:
    return _page(
        "连接网络",
        "<h1>请从 Wi-Fi 门户打开本页</h1>"
        "<p>直接访问这个地址时没有 openNDS 客户端参数。"
        " Open this page from the captive portal after connecting to Wi-Fi.</p>",
    )


def make_handler(app: PortalApp):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):
            app.handle(self)

        def do_POST(self):
            app.handle(self)

        def log_message(self, fmt, *args):
            message = fmt % args
            message = re.sub(r"(code=)[^&\s]+", r"\1***", message)
            message = re.sub(r"(fas=)[^&\s]+", r"\1***", message)
            log.info("%s %s", self.address_string(), message)

    return Handler


def serve(config: Config, app: PortalApp | None = None) -> None:
    portal = app or PortalApp(config)
    if config.dry_run:
        log.warning("FEISHU_DRY_RUN=1: codes are shown on the portal page and are not sent to Feishu")
    class ReuseServer(ThreadingHTTPServer):
        allow_reuse_address = True

    server = ReuseServer((config.listen, config.port), make_handler(portal))
    server.daemon_threads = True
    log.info(
        "fas-lark listening on %s:%s api=%s dry_run=%s credentials=%s verification_token=%s encrypt_key=%s",
        config.listen,
        config.port,
        config.api_base,
        config.dry_run,
        config.credentials_configured,
        bool(config.verification_token),
        bool(config.encrypt_key),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("stopping")
    finally:
        server.server_close()


def check_config(config: Config, ping: bool) -> int:
    print(f"config ok api_base={config.api_base} dry_run={config.dry_run}")
    print(f"credentials_configured={config.credentials_configured}")
    print(f"verification_token_configured={bool(config.verification_token)}")
    print(f"encrypt_key_configured={bool(config.encrypt_key)}")
    if not ping:
        return 0
    if config.dry_run:
        print("skipped Feishu token request because FEISHU_DRY_RUN=1")
        return 0
    try:
        FeishuClient(config).tenant_token()
    except (FeishuError, ConfigError) as exc:
        print(f"feishu check failed: {exc.__class__.__name__}")
        return 3
    print("feishu token ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="openNDS Feishu/Lark OTP portal")
    parser.add_argument("--check", action="store_true", help="validate configuration and exit")
    parser.add_argument("--check-feishu", action="store_true", help="also request a tenant access token")
    args = parser.parse_args(argv)
    logging.basicConfig(level=os.environ.get("FAS_LOG_LEVEL", "INFO"), format="%(levelname)s %(message)s")
    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.check or args.check_feishu:
        return check_config(config, args.check_feishu)
    serve(config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
