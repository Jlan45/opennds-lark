#!/usr/bin/env python3
# Copyright (C) 2026 the opennds-lark contributors
# Released under the GNU GPL version 2.

"""Unit and localhost checks for the Feishu/Lark OTP FAS. No network calls."""

from __future__ import annotations

import base64
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fas_lark


FASKEY = "0123456789abcdef"
HID = "ab" * 32


def mapping(**overrides):
    data = {
        "OPENNDS_FASKEY": FASKEY,
        "FEISHU_APP_ID": "cli_testapp1",
        "FEISHU_APP_SECRET": "test-secret-value",
        "FEISHU_DRY_RUN": "0",
        "FAS_LISTEN": "127.0.0.1",
        "FAS_PORT": "2080",
        "OTP_RESEND_SECONDS": "0",
        "OTP_MAX_SENDS_PER_IP": "30",
        "OTP_MAX_SENDS_PER_ID": "30",
        "OTP_TTL_SECONDS": "300",
        "OTP_MAX_ATTEMPTS": "3",
        "OTP_LENGTH": "6",
    }
    data.update(overrides)
    return data


class TokenTests(unittest.TestCase):
    def test_matches_sha256sum_used_by_opennds(self):
        if shutil.which("sha256sum") is None:
            self.skipTest("sha256sum is not installed")
        raw = (HID + FASKEY).encode("utf-8")
        output = subprocess.check_output(["sha256sum"], input=raw)
        digest = output.split()[0].decode("ascii")
        self.assertEqual(fas_lark.auth_token(HID, FASKEY), digest)
        self.assertEqual(len(digest), 64)

    def test_blob_roundtrip_uses_comma_space(self):
        blob = fas_lark.demo_fas_blob(hid=HID, gatewayname="Cafe, North")
        decoded = base64.b64decode(blob).decode("utf-8")
        self.assertIn(", ", decoded)
        self.assertNotIn(", Cafe", decoded)
        fields = fas_lark.parse_fas_blob(blob)
        self.assertEqual(fields["hid"], HID)
        self.assertEqual(fields["gatewayaddress"], "192.168.1.1:2050")
        self.assertEqual(urllib.parse.unquote(fields["gatewayname"]), "Cafe, North")

    def test_plus_and_slash_survive_query_decoding(self):
        # High bytes push standard base64 into using both '+' and '/'.
        blob = fas_lark.build_fas_blob(
            {
                "hid": HID,
                "clientip": "10.0.0.8",
                "clientmac": "aa:bb:cc:dd:ee:ff",
                "gatewayaddress": "192.168.1.1:2050",
                "pad": "".join(chr(i) for i in range(160, 256)),
            }
        )
        self.assertIn("+", blob)
        self.assertIn("/", blob)
        parsed = urllib.parse.parse_qs(urllib.parse.urlencode({"fas": blob}))
        self.assertEqual(fas_lark.parse_fas_blob(parsed["fas"][0])["hid"], HID)

    def test_gateway_address_shape(self):
        self.assertTrue(fas_lark.valid_gateway_address("192.168.1.1:2050"))
        self.assertTrue(fas_lark.valid_gateway_address("[2001:db8::1]:2050"))
        self.assertFalse(fas_lark.valid_gateway_address("192.168.1.1"))
        self.assertFalse(fas_lark.valid_gateway_address("evil.example/opennds_auth:80"))
        self.assertFalse(fas_lark.valid_gateway_address("javascript:alert(1)"))
        self.assertFalse(fas_lark.valid_gateway_address("127.0.0.1:2050/extra"))


class IdentityTests(unittest.TestCase):
    def test_mobile_and_email(self):
        self.assertEqual(fas_lark.normalize_identity("mobile", "13800138000"), "+8613800138000")
        self.assertEqual(fas_lark.normalize_identity("mobile", "+65 8123-4567"), "+6581234567")
        self.assertEqual(fas_lark.normalize_identity("email", "Ada@Example.COM"), "ada@example.com")
        with self.assertRaises(fas_lark.PortalError):
            fas_lark.normalize_identity("open_id", "not-an-open-id")
        self.assertTrue(fas_lark.normalize_identity("open_id", "ou_abc12345").startswith("ou_"))


class ConfigTests(unittest.TestCase):
    def test_accepts_feishu_and_lark_bases_only(self):
        feishu = fas_lark.Config.from_mapping(mapping(FEISHU_API_BASE="https://open.feishu.cn/"))
        lark = fas_lark.Config.from_mapping(mapping(FEISHU_API_BASE="https://open.larksuite.com"))
        self.assertEqual(feishu.api_base, "https://open.feishu.cn")
        self.assertEqual(lark.api_base, "https://open.larksuite.com")
        for bad in ("http://open.feishu.cn", "https://evil.example", "https://user:pw@open.feishu.cn"):
            with self.assertRaises(fas_lark.ConfigError):
                fas_lark.Config.from_mapping(mapping(FEISHU_API_BASE=bad))

    def test_secrets_come_from_the_environment_file_without_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "fas-lark.env"
            env_file.write_text(
                "\n".join(
                    [
                        "OPENNDS_FASKEY=fromfilefromfile",
                        "FEISHU_APP_ID=cli_fromfile",
                        "FEISHU_APP_SECRET=fromfile-secret",
                        "FEISHU_VERIFICATION_TOKEN=verifytoken",
                        "FEISHU_ENCRYPT_KEY=encryptkeyvalue",
                        "FEISHU_DRY_RUN=1",
                    ]
                ),
                encoding="utf-8",
            )
            loaded = fas_lark.Config.from_env({"FAS_LARK_ENV_FILE": str(env_file)})
            self.assertEqual(loaded.faskey, "fromfilefromfile")
            self.assertEqual(loaded.verification_token, "verifytoken")
            self.assertTrue(loaded.encrypt_key)
            pinned = fas_lark.Config.from_env(
                {"FAS_LARK_ENV_FILE": str(env_file), "OPENNDS_FASKEY": "fromenvfromenv00", "FEISHU_DRY_RUN": "1"}
            )
            self.assertEqual(pinned.faskey, "fromenvfromenv00")

    def test_dry_run_may_omit_app_credentials(self):
        config = fas_lark.Config.from_mapping(
            {"OPENNDS_FASKEY": FASKEY, "FEISHU_DRY_RUN": "1", "FEISHU_APP_ID": "", "FEISHU_APP_SECRET": ""}
        )
        self.assertTrue(config.dry_run)
        with self.assertRaises(fas_lark.ConfigError):
            fas_lark.Config.from_mapping({"OPENNDS_FASKEY": FASKEY, "FEISHU_DRY_RUN": "0"})

    def test_check_cli_does_not_print_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "fas-lark.env"
            env_file.write_text(
                "OPENNDS_FASKEY=fromfilefromfile\nFEISHU_APP_ID=cli_fromfile\n"
                "FEISHU_APP_SECRET=supersecretvalue\nFEISHU_VERIFICATION_TOKEN=verifytoken\n"
                "FEISHU_ENCRYPT_KEY=encryptkeyvalue\n",
                encoding="utf-8",
            )
            buffer = __import__("io").StringIO()
            with mock.patch.dict(os.environ, {"FAS_LARK_ENV_FILE": str(env_file)}, clear=True):
                with mock.patch("sys.stdout", buffer):
                    status = fas_lark.main(["--check"])
            text = buffer.getvalue()
            self.assertEqual(status, 0)
            self.assertNotIn("supersecretvalue", text)
            self.assertNotIn("verifytoken", text)
            self.assertNotIn("encryptkeyvalue", text)
            self.assertIn("verification_token_configured=True", text)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = {"now": 1_700_000_000}
        self.config = fas_lark.Config.from_mapping(
            mapping(OTP_STORE_PATH=str(Path(self.tmp.name) / "otp.json"), OTP_RESEND_SECONDS="60")
        )
        self.store = fas_lark.OtpStore(self.config, now=lambda: self.clock["now"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_code_is_hashed_and_one_time(self):
        self.store.begin_send("10.0.0.8", "email:ada@example.com")
        self.store.save_code(HID, "10.0.0.8", "email", "ada@example.com", "123456")
        raw = Path(self.config.store_path).read_text(encoding="utf-8")
        saved = json.loads(raw)
        entry = saved["otps"][HID]
        self.assertNotIn("123456", entry.values())
        self.assertEqual(len(entry["digest"]), 64)
        self.assertEqual(os.stat(self.config.store_path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.tmp.name).st_mode & 0o777, 0o700)
        self.assertEqual(self.store.verify(HID, "10.0.0.9", "email", "ada@example.com", "123456"), "ip")
        self.assertEqual(self.store.verify(HID, "10.0.0.8", "email", "ada@example.com", "000000"), "wrong")
        self.assertEqual(self.store.verify(HID, "10.0.0.8", "email", "ada@example.com", "123456"), "ok")
        self.assertEqual(self.store.verify(HID, "10.0.0.8", "email", "ada@example.com", "123456"), "missing")

    def test_expiry_lockout_and_rate_limit(self):
        self.store.begin_send("10.0.0.8", "email:ada@example.com")
        self.store.save_code(HID, "10.0.0.8", "email", "ada@example.com", "123456")
        self.clock["now"] += 301
        self.assertEqual(self.store.verify(HID, "10.0.0.8", "email", "ada@example.com", "123456"), "expired")

        self.clock["now"] += 3600
        self.store.begin_send("10.0.0.8", "email:ada@example.com")
        self.store.save_code(HID, "10.0.0.8", "email", "ada@example.com", "654321")
        self.assertEqual(self.store.verify(HID, "10.0.0.8", "email", "ada@example.com", "1"), "wrong")
        self.assertEqual(self.store.verify(HID, "10.0.0.8", "email", "ada@example.com", "2"), "wrong")
        self.assertEqual(self.store.verify(HID, "10.0.0.8", "email", "ada@example.com", "3"), "locked")

        self.clock["now"] += 1
        with self.assertRaises(fas_lark.PortalError):
            self.store.begin_send("10.0.0.8", "email:ada@example.com")


class ScriptedApi:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        status, payload = self.responses.pop(0)
        return status, json.dumps(payload).encode("utf-8")


def token_response(token):
    return 200, {"code": 0, "tenant_access_token": token, "expire": 7200}


class FeishuClientTests(unittest.TestCase):
    def test_email_send_uses_tenant_token_and_string_content(self):
        config = fas_lark.Config.from_mapping(mapping())
        api = ScriptedApi(
            [
                token_response("t-1"),
                (200, {"code": 0, "data": {"message_id": "om_1"}}),
                (200, {"code": 0, "data": {"message_id": "om_2"}}),
            ]
        )
        client = fas_lark.FeishuClient(config, opener=api)
        client.send_login_code("email", "ada@example.com", "654321")
        client.send_login_code("user_id", "zhangsan", "111111")
        self.assertEqual(len(api.requests), 3)
        token_call, first, second = api.requests
        self.assertTrue(token_call.full_url.endswith("/open-apis/auth/v3/tenant_access_token/internal"))
        self.assertIsNone(token_call.get_header("Authorization"))
        self.assertEqual(json.loads(token_call.data)["app_secret"], "test-secret-value")
        self.assertIn("receive_id_type=email", first.full_url)
        self.assertEqual(first.get_header("Authorization"), "Bearer t-1")
        body = json.loads(first.data)
        self.assertEqual(body["receive_id"], "ada@example.com")
        self.assertEqual(body["msg_type"], "text")
        self.assertIn("654321", json.loads(body["content"])["text"])
        self.assertIn("receive_id_type=user_id", second.full_url)
        self.assertEqual(second.get_header("Authorization"), "Bearer t-1")

    def test_mobile_is_resolved_to_open_id(self):
        config = fas_lark.Config.from_mapping(mapping(FEISHU_API_BASE="https://open.larksuite.com"))
        api = ScriptedApi(
            [
                token_response("t-1"),
                (200, {"code": 0, "data": {"user_list": [{"mobile": "+8613800138000", "user_id": "ou_abc12345"}]}}),
                (200, {"code": 0, "data": {"message_id": "om_1"}}),
            ]
        )
        client = fas_lark.FeishuClient(config, opener=api)
        client.send_login_code("mobile", "+8613800138000", "222222")
        self.assertIn("open.larksuite.com", api.requests[1].full_url)
        self.assertIn("/open-apis/contact/v3/users/batch_get_id?user_id_type=open_id", api.requests[1].full_url)
        self.assertEqual(json.loads(api.requests[1].data)["mobiles"], ["+8613800138000"])
        self.assertIn("receive_id_type=open_id", api.requests[2].full_url)
        self.assertEqual(json.loads(api.requests[2].data)["receive_id"], "ou_abc12345")

    def test_unknown_user_and_token_refresh(self):
        config = fas_lark.Config.from_mapping(mapping())
        missing = ScriptedApi(
            [
                token_response("t-1"),
                (200, {"code": 0, "data": {"user_list": [{"mobile": "+8613800138000"}]}}),
            ]
        )
        client = fas_lark.FeishuClient(config, opener=missing)
        with self.assertRaises(fas_lark.FeishuError) as caught:
            client.send_login_code("mobile", "+8613800138000", "222222")
        self.assertIn("无法向该飞书账号发送验证码", caught.exception.public)

        refreshed = ScriptedApi(
            [
                token_response("t-1"),
                (400, {"code": 99991663, "msg": "invalid"}),
                token_response("t-2"),
                (200, {"code": 0, "data": {"message_id": "om_2"}}),
            ]
        )
        client = fas_lark.FeishuClient(config, opener=refreshed)
        client.send_login_code("email", "ada@example.com", "654321")
        self.assertEqual(refreshed.requests[-1].get_header("Authorization"), "Bearer t-2")

    def test_redirect_is_not_followed(self):
        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1/stolen-secret")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, fmt, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/token"
            request = urllib.request.Request(url, data=b"{}", method="POST")
            with self.assertRaises(fas_lark.FeishuError):
                fas_lark.default_opener()(request, timeout=2)
        finally:
            server.shutdown()
            server.server_close()


class CapturingFeishu:
    def __init__(self):
        self.sent = []

    def send_login_code(self, id_type, identifier, code):
        self.sent.append((id_type, identifier, code))


class HttpFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.feishu = CapturingFeishu()
        cls.config = fas_lark.Config.from_mapping(
            mapping(OTP_STORE_PATH=str(Path(cls.tmp.name) / "otp.json"), OTP_MAX_ATTEMPTS="4")
        )
        cls.app = fas_lark.PortalApp(cls.config, feishu=cls.feishu)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), fas_lark.make_handler(cls.app))
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, method, path, form=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = None
        headers = {}
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read().decode("utf-8")
        status = response.status
        connection.close()
        return status, payload

    def test_portal_flow_grants_opennds_token(self):
        status, health = self.request("GET", "/health")
        self.assertEqual(status, 200)
        parsed = json.loads(health)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["api_base"], "https://open.feishu.cn")
        self.assertNotIn(FASKEY, health)
        self.assertNotIn("test-secret-value", health)

        status, orphan = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("Wi-Fi", orphan)

        status, online = self.request("GET", "/?status=authenticated")
        self.assertIn("已经可以上网", online)

        hostile_name = "<script>alert(1)</script>"
        blob = fas_lark.demo_fas_blob(hid=HID, gatewayname=hostile_name)
        status, page = self.request("GET", "/?" + urllib.parse.urlencode({"fas": blob}))
        self.assertEqual(status, 200)
        self.assertNotIn("<script>", page)
        self.assertIn("获取验证码", page)
        self.assertIn('name="fas"', page)
        status, prefixed = self.request("GET", "/fas-lark?" + urllib.parse.urlencode({"fas": blob}))
        self.assertIn('action="/fas-lark"', prefixed)

        status, reflected = self.request(
            "POST",
            "/",
            {"fas": blob, "action": "request", "id_type": "email", "id_value": '"><img src=x>'},
        )
        self.assertNotIn("<img", reflected)
        self.assertIn("&lt;img", reflected)

        status, sent = self.request(
            "POST",
            "/",
            {"fas": blob, "action": "request", "id_type": "email", "id_value": "Ada@Example.COM"},
        )
        self.assertEqual(self.feishu.sent[-1][0], "email")
        self.assertEqual(self.feishu.sent[-1][1], "ada@example.com")
        code = self.feishu.sent[-1][2]
        self.assertNotIn(code, sent)
        self.assertIn("验证码已通过飞书机器人发送", sent)

        status, wrong = self.request(
            "POST",
            "/",
            {
                "fas": blob,
                "action": "verify",
                "id_type": "email",
                "id_value": "ada@example.com",
                "code": "000000",
            },
        )
        self.assertIn("验证码不正确", wrong)
        self.assertNotIn('name="tok"', wrong)

        status, granted = self.request(
            "POST",
            "/",
            {
                "fas": blob,
                "action": "verify",
                "id_type": "email",
                "id_value": "ada@example.com",
                "code": code,
            },
        )
        self.assertIn("验证通过", granted)
        self.assertIn('action="http://192.168.1.1:2050/opennds_auth/"', granted)
        self.assertIn(f'name="tok" value="{fas_lark.auth_token(HID, FASKEY)}"', granted)
        self.assertIn('name="redir" value="http://192.168.1.1:2050/?landing=1"', granted)
        custom = urllib.parse.unquote(granted.split('name="custom" value="', 1)[1].split('"', 1)[0])
        self.assertEqual(
            base64.b64decode(custom).decode("utf-8"),
            "feishu_id_type=email, feishu_id=ada@example.com",
        )
        saved = json.loads(Path(self.config.store_path).read_text(encoding="utf-8"))
        self.assertNotIn(HID, saved["otps"])

        status, replay = self.request(
            "POST",
            "/",
            {
                "fas": blob,
                "action": "verify",
                "id_type": "email",
                "id_value": "ada@example.com",
                "code": code,
            },
        )
        self.assertIn("请先获取验证码", replay)
        self.assertNotIn('name="tok"', replay)

    def test_dry_run_shows_the_code_without_calling_feishu(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = fas_lark.Config.from_mapping(
            mapping(
                FEISHU_DRY_RUN="1",
                FEISHU_APP_ID="",
                FEISHU_APP_SECRET="",
                OTP_STORE_PATH=str(Path(tmp.name) / "otp.json"),
                FAS_PUBLIC_HOST="status.client:2080",
            )
        )
        app = fas_lark.PortalApp(config)
        server = ThreadingHTTPServer(("127.0.0.1", 0), fas_lark.make_handler(app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        blob = fas_lark.demo_fas_blob(hid="cd" * 32)
        body = urllib.parse.urlencode(
            {"fas": blob, "action": "request", "id_type": "open_id", "id_value": "ou_abc12345"}
        )
        connection.request("POST", "/", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        page = connection.getresponse().read().decode("utf-8")
        connection.close()
        self.assertIn("演练模式", page)
        shown = page.split('class="otp">', 1)[1].split("<", 1)[0]
        self.assertEqual(len(shown), 6)
        self.assertTrue(shown.isdigit())
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        verify = urllib.parse.urlencode(
            {
                "fas": blob,
                "action": "verify",
                "id_type": "open_id",
                "id_value": "ou_abc12345",
                "code": shown,
            }
        )
        connection.request("POST", "/", body=verify, headers={"Content-Type": "application/x-www-form-urlencoded"})
        granted = connection.getresponse().read().decode("utf-8")
        connection.close()
        self.assertIn('name="redir" value="http://status.client:2080/?landing=1"', granted)
        self.assertIn(fas_lark.auth_token("cd" * 32, FASKEY), granted)


if __name__ == "__main__":
    unittest.main()
