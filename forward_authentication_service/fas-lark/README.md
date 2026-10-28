# 飞书 / Lark 一次性验证码 FAS

这是 openNDS 的一个 **level 1 Forward Authentication Service**。它不替换 `forward_authentication_service/PreAuth/` 里的默认 ThemeSpec，也不改 C 守护进程。openNDS 仍负责跳转和最终放行；本目录只负责“认人 + 发验证码”。

English summary is at the bottom.

## 门户流程

1. 客户端连上被门户接管的网络，openNDS 把它重定向到 `http://<fasremoteip 或 fasremotefqdn>:2080/?fas=<base64>`。
2. 解码后的参数与 `fas-hid.php` 相同，分隔符是逗号加空格。其中 `hid` 是客户端 token 的 sha256，真正的 token 不会出现。
3. 用户选择飞书邮箱、手机号、`open_id`、`user_id` 或 `union_id`。
4. FAS 生成 6 位数字验证码（默认 300 秒），只把 HMAC 写入 `OTP_STORE_PATH`，然后调用飞书或 Lark 的机器人发消息接口。
5. 用户提交验证码。同一来源 IP、同一个 `hid`、同一次身份才算通过。错误次数用尽、过期或用过之后，验证码失效。
6. 通过后页面给出 openNDS 既有的授权表单：

```
GET http://<gatewayaddress>/opennds_auth/?tok=<sha256(hid + faskey)>&redir=...&custom=<base64>
```

`gatewayaddress` 来自 openNDS，本身已包含端口（例如 `192.168.1.1:2050`）。`tok` 与守护进程里的 `sha256sum`、以及 `fas-hid.php` 的 `hash('sha256', hid.key)` 是同一种摘要。`custom` 解码后是 `feishu_id_type=... , feishu_id=...`，BinAuth 日志能看到它，里面没有验证码。

未实现 level 2/3 的 AES，也未实现 level 4 的 authmon。本地 http 门户用 level 1 即可，不需要 PHP 或 OpenSSL。

## 创建飞书应用

国内飞书：<https://open.feishu.cn/app>  
国际版 Lark：<https://open.larksuite.com/app>，接口路径相同，只改 `FEISHU_API_BASE`。

1. 创建企业自建应用，启用**机器人**。
2. 权限：
   - `im:message:send_as_bot`：以应用身份发消息。邮箱、open_id、user_id、union_id 都需要。
   - `contact:user.id:readonly`：通过手机号或邮箱获取用户 ID。手机号必开。邮箱默认直接用 `receive_id_type=email`，不必开这个权限；若邮箱直发失败，把 `FEISHU_RESOLVE_EMAIL=1` 并加上该权限。
3. **可用范围**包含要上网的成员。发布版本，让管理员审批通过。
4. 事件订阅的 Verification Token、Encrypt Key 不是发送验证码的必要条件。已经生成的话放进环境变量，不要写进仓库。`/health` 只报告它们“是否已配置”。本 FAS 不提供事件回调。

验证码进的是机器人私聊，不是短信。查不到的人、已离职的人、不在可用范围内的人，以及外部访客，都收不到。门户对用户只显示同一句失败说明，具体错误码写在 FAS 日志里。

## 环境变量

复制 `fas-lark.env.example` 为 `/etc/opennds/fas-lark.env`，`chmod 600`。用 `FAS_LARK_ENV_FILE` 指向它，或由 systemd `EnvironmentFile=` 注入。已经存在于进程环境里的变量优先于文件。

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `OPENNDS_FASKEY` | 是 | 与 `option faskey` 相同，8–256 位字母或数字。`openssl rand -hex 32` |
| `FEISHU_APP_ID` | 正式环境 | 应用 App ID |
| `FEISHU_APP_SECRET` | 正式环境 | 应用 App Secret |
| `FEISHU_VERIFICATION_TOKEN` | 否 | 事件订阅 Verification Token |
| `FEISHU_ENCRYPT_KEY` | 否 | 事件订阅 Encrypt Key |
| `FEISHU_API_BASE` | 否 | 默认 `https://open.feishu.cn`。Lark 用 `https://open.larksuite.com`。其它地址会被拒绝 |
| `FEISHU_DRY_RUN` | 否 | `1` 时页面直接显示验证码，不访问飞书。上线前必须关掉 |
| `FEISHU_RESOLVE_EMAIL` | 否 | `1` 时先把邮箱解析成 open_id |
| `FAS_LISTEN` / `FAS_PORT` | 否 | 默认 `0.0.0.0:2080`。不能用 80 |
| `FAS_PUBLIC_HOST` | 否 | 例如 `status.client:2080`。设置后，授权完成跳回本 FAS 的落地页 |
| `OPENNDS_GATEWAY_ADDRESS` | 否 | 例如 `192.168.1.1:2050`。设置后，blob 里的网关地址必须一致 |
| `OPENNDS_AUTHDIR` | 否 | 默认 `opennds_auth` |
| `OTP_TTL_SECONDS` | 否 | 默认 300，范围 30–1800 |
| `OTP_STORE_PATH` | 否 | 默认 `/tmp/opennds-lark/otp.json`，目录 `0700`、文件 `0600`。重启即清空，这是预期行为 |

依赖只有 Python 3 标准库。小闪存的 OpenWrt 上安装 `python3` 会占不少空间，可以把 FAS 放在同一局域网里、且自身不经过 captive portal 的机器上。

调用飞书的是 FAS 主机的出口，不是客户端。不要把 `open.feishu.cn` 加进 walled garden，也不要把 2080 端口转发到公网。限流按 TCP 来源地址和目标身份计算，伪造 `fas` 参数里的 MAC 绕不过去。

## 和 openNDS 一起跑

片段在 `opennds.conf.snippet`，systemd 示例在 `fas-lark.service.example`。

先在 openNDS 配置里**显式写上** `faskey` 再启动。若留空，守护进程会自己生成并追加到 `/etc/config/opennds`。两边必须是同一个值：

```
uci get opennds.@opennds[0].faskey
```

网关本机（最常见）：

- `fasport` `2080`
- `faspath` `/`
- `fas_secure_enabled` `1`
- `login_option_enabled` `0`（默认 ThemeSpec 因此不会被选中）
- `fasremoteip` = 网关 LAN 地址，也就是日志里 `Interface br-lan is at ...` 的那个地址，不是 `127.0.0.1`
- `fasremotefqdn` = `gatewayfqdn`。默认是 `status.client`。两者相等时，openNDS 才会在 `ndsRTR` 上放行该端口
- `list users_to_router 'allow tcp port 2080'`，挡在这条链最后的 reject 之前

FAS 在另一台局域网主机上时：`fasremoteip` 填那台主机，`fasremotefqdn` 保持 `disabled`。预认证客户端会被放行访问该地址，不需要 `users_to_router` 那条端口规则。那台主机自己要能访问飞书。

```
install -d /usr/lib/opennds/fas-lark
install -m 0755 fas_lark.py /usr/lib/opennds/fas-lark/fas_lark.py
install -m 0600 /etc/opennds/fas-lark.env /etc/opennds/fas-lark.env
FAS_LARK_ENV_FILE=/etc/opennds/fas-lark.env python3 /usr/lib/opennds/fas-lark/fas_lark.py --check
FAS_LARK_ENV_FILE=/etc/opennds/fas-lark.env python3 /usr/lib/opennds/fas-lark/fas_lark.py --check-feishu
FAS_LARK_ENV_FILE=/etc/opennds/fas-lark.env python3 /usr/lib/opennds/fas-lark/fas_lark.py
```

然后 `uci commit opennds && service opennds restart`。客户端看到的地址是 `http://status.client:2080/?fas=...`（或你设置的 FQDN）。

改回默认“点击继续”：

```
uci set opennds.@opennds[0].login_option_enabled='1'
uci delete opennds.@opennds[0].fasport
uci commit opennds
service opennds restart
```

## 演练模式

`FEISHU_DRY_RUN=1` 可以不填 App ID。验证码只出现在门户页面上，日志不打印验证码本身。用它确认页面和 `tok`，不能代替真实客户端授权：演示 blob 里的 `hid` 不是在线客户端的 `hid`，openNDS 会拒绝这个 `tok`。

```
cd forward_authentication_service/fas-lark
OPENNDS_FASKEY=0123456789abcdef FEISHU_DRY_RUN=1 FAS_PORT=2080 python3 fas_lark.py
```

另一个终端：

```
python3 - << 'PY'
import fas_lark
print(fas_lark.demo_fas_blob(gatewayaddress="192.168.1.1:2050"))
PY
```

浏览器打开 `http://127.0.0.1:2080/?fas=<上面的输出>`。正式使用前把 `FEISHU_DRY_RUN` 设回 `0`。

## 冒烟测试清单

- [ ] `cd forward_authentication_service/fas-lark && python3 -m unittest test_fas_lark.py -v` 全部通过。测试不访问网络，并用 `sha256sum` 对照 `tok`。
- [ ] `python3 fas_lark.py --check` 只打印配置是否齐全，不打印 App Secret、Verification Token、Encrypt Key 或 faskey。
- [ ] 填入真实凭证后 `python3 fas_lark.py --check-feishu` 打印 `feishu token ok`。
- [ ] 演练模式能打开发码页、看到验证码、提交后出现“开始上网”，表单地址是 `http://<gatewayaddress>/opennds_auth/`，`tok` 为 64 位十六进制。
- [ ] 关掉演练模式。手机连上 Wi-Fi，门户自动打开。用企业内、且在可用范围内的邮箱或手机号收取机器人私聊。
- [ ] 输入验证码并点击“开始上网”。手机可以访问外网。
- [ ] `ndsctl json` 里该客户端已认证。`custom` 用 base64 解码后能看到 `feishu_id_type` 和 `feishu_id`，没有验证码。
- [ ] 错误验证码连续 5 次后必须重新获取。过期、换一台设备、再提交同一次验证码，都不会放行。
- [ ] 不在企业内的手机号失败，且飞书里没有消息。
- [ ] 按上一节恢复 `login_option_enabled=1` 并删除 `fasport` 后，默认点击继续页面仍在。

## 许可

GNU GPL version 2，与上游 openNDS 一致。见仓库根目录 `COPYING`。

## English

This is a fas_secure level 1 FAS. openNDS redirects the client here with the same base64 `fas` blob `fas-hid.php` parses. The page collects a Feishu/Lark email, mobile, open_id, user_id, or union_id. The bot sends a short-lived code in a private chat (not SMS). The person must belong to the tenant and sit inside the app's availability. After the code matches, the browser is given the normal auth form:

`http://<gatewayaddress>/opennds_auth/?tok=<sha256(hid + faskey)>&redir=...&custom=...`

`OPENNDS_FASKEY` must equal `option faskey`. `FEISHU_API_BASE` is either `https://open.feishu.cn` or `https://open.larksuite.com`. App ID, App Secret, verification token, and encrypt key are environment variables; the last two are optional and unused by the send path. On the gateway itself set `fasremoteip` to the LAN address, `fasremotefqdn` to `gatewayfqdn` (default `status.client`), `fasport` to `2080`, `faspath` to `/`, `fas_secure_enabled` to `1`, and allow TCP 2080 in `users_to_router`. Leave the default ThemeSpec in place for sites that do not set `fasport`. `FEISHU_DRY_RUN=1` paints the code on the page so the handshake can be checked before real credentials are installed. The checklist above is the smoke test.
