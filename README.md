## 1. The openNDS project

openNDS (open Network Demarcation Service) is a high performance, small footprint, Captive Portal.

It provides a border control gateway between a public local area network and the Internet.

It supports all ranges between small stand alone venues through to large mesh networks with multiple portal entry points.

Both the client driven Captive Portal Detection (CPD) method and gateway driven Captive Portal Identification method (CPI - RFC 8910 and RFC 8908) are supported.

In its default configuration, openNDS offers a dynamically generated and adaptive splash page sequence. Internet access is granted by a click to continue button, accepting Terms of Service. A simple option enables input forms for user login.

The package incorporates the FAS API allowing many flexible customisation options.

The creation of sophisticated third party authentication applications is fully supported.

Internet hosted **https portals** can be implemented with no security errors, to inspire maximum user confidence.

## 2. Captive Portal Detection (CPD) and Captive Portal Identification (CPI)

**2.1 CPD**

Captive Portal Detection (CPD) is a client driven process available on all modern mobile devices, most desktop operating systems and most browsers. The CPD process automatically issues a port 80 request on connection to a network as a means of probing for a captive state.

Sometimes known as a "canary test", this process, driven by the client, has evolved over a number of years to be a reliable de-facto standard.
openNDS detects this probing and serves a special "**splash**" web page sequence to the connecting client device.

**2.2 CPI  - RFC 8910 and RFC 8908**

Captive Portal Identification (CPI) is a Gateway driven process as defined in standards RFC8910 (Captive-Portal Identification in DHCP and Router Advertisements) and RFC8908 (Captive Portal API).

A gateway router informs a connecting client that it is in a captive state by providing a url at which a client can access for authentication.

A client may access this url to be served the same portal "**splash**" page sequence as it would have in the traditional CPD method.

Alternatively, a client may use this url to access the RFC8908 Captive Portal API, ultimately being served a splash page sequence for authentication.

From openNDS v9.5.0, The CPI method is supported in both forms and enabled by default. It can be disabled as a config option.

**Note:** Very few client devices support CPI at the time of writing (November 2021)

## 3. Zero Configuration Click to Continue Default

Immediately after installing, a simple three stage dynamic html splash page sequence is served to connecting clients. Client logins are recorded in a log.

 * The first page asks the user to accept the portal Terms of Service.
 * The second page welcomes the user.
 * Depending on the client device CPD implementation, a third page may be displayed. It confirms the user has access to the Internet.

## 4. Username/Email-address Login Default. (*Enabled in the configuration file*)

Very similar to the Click to Continue default, this option has an initial "login page" that presents a form to the user where they must enter a name and email address.

## 5. Data and Data Rate Quotas

Data volume and data rate thresholds are supported without additional dependencies, independently for both upload and download with configurable default values for all clients, or specific values per client.

If a data volume threshold is exceeded the client will be deauthenticated.

If a rate threshold is exceeded, a dynamic bucket filter is used, per client, to limit data rates at a packet level, either limiting rates close to the threshold or by increasing the bucket size at the expense of increased latency.

Third party traffic control packages can also be used, for example to provide system wide rate ceilings, at the same time as the built in thresholds.

## 6. Customisation

Many methods of customising openNDS exist:

 * **simple changes to content** using basic html and css edits.
 * **theme specifications** allowing full control of look and feel with the option of configuration defined form fields generating dynamic html.
 * **full third party development** where openNDS is used as the "Engine" behind the most sophisticated Captive Portal systems.

## 6. The Portal

The portal component of openNDS is its **Forward Authentication Service (FAS)**.

FAS provides user validation/authentication in the form of a set of dynamic web pages.

These web pages may be served by openNDS itself, or served by a third party web server. The third party web server may be located remotely on the Internet, on the local area network or on the openNDS router.

The default "Click to continue" and "Username/Email-address Login" options are examples where openNDS serves the splash page sequence itself.

## 7. Documentation

For full documentation please see https://opennds.rtfd.io/

You can select either *Stable*, *Latest* or the historical documentation of *older versions*.

## 8. Feishu / Lark one-time code (this fork)

本分支在 `forward_authentication_service/fas-lark/` 增加了一个独立的 FAS，不改默认 ThemeSpec。用户在门户里填写飞书邮箱、手机号或 open_id / user_id / union_id，网关侧脚本向飞书（或国际版 Lark）机器人发一条短时验证码；验证通过后，按 openNDS level 1 的既有握手提交 `tok = sha256(hid + faskey)` 到 `http://<gatewayaddress>/opennds_auth/`。

验证码是机器人私聊，不是短信。对方必须是本企业通讯录里的用户，并且落在应用可用范围内。

### 飞书应用

1. 在 [飞书开放平台](https://open.feishu.cn/app) 创建企业自建应用，并启用机器人。国际版 Lark 用 [open.larksuite.com](https://open.larksuite.com/app)，接口路径相同。
2. 开通权限 **im:message:send_as_bot**（以应用身份发消息）。用手机号查找，或把 `FEISHU_RESOLVE_EMAIL=1` 时，再开通 **contact:user.id:readonly**（通过手机号或邮箱获取用户 ID）。
3. 把可用范围设为需要上网的成员，创建版本并发布，等待管理员通过。
4. 事件订阅用的 Verification Token 和 Encrypt Key 可以留空。发送验证码用不到它们；如果已经有这两个值，放进环境变量，不要写进代码。

### 环境变量与运行

复制 `forward_authentication_service/fas-lark/fas-lark.env.example` 为 `/etc/opennds/fas-lark.env`（权限 `0600`）。至少填入：

| 变量 | 作用 |
| --- | --- |
| `OPENNDS_FASKEY` | 与 openNDS `option faskey` 完全相同，仅字母和数字 |
| `FEISHU_APP_ID` / `FEISHU_APP_SECRET` | 应用凭证 |
| `FEISHU_API_BASE` | 飞书 `https://open.feishu.cn`，Lark `https://open.larksuite.com` |
| `FAS_PORT` | 默认 `2080`，不要用 80 |

在网关或一台不被门户拦截的局域网主机上：

```
python3 fas_lark.py --check
python3 fas_lark.py --check-feishu
python3 fas_lark.py
```

标准库即可，不需要额外的 Python 包。FAS 进程访问飞书；客户端不需要把 `open.feishu.cn` 放进 walled garden，也不要把 2080 映射到公网。

### openNDS

`fas_secure_enabled` 必须是 **1**。网关本机运行时，`fasremoteip` 要等于网关 LAN 地址，`fasremotefqdn` 要等于 `gatewayfqdn`（默认 `status.client`），否则 ndsRTR 链末尾的 reject 会丢掉 2080。同时加上 `list users_to_router 'allow tcp port 2080'`。`login_option_enabled` 设为 `0`，避免继续走默认 ThemeSpec。可粘贴的片段在 `forward_authentication_service/fas-lark/opennds.conf.snippet`。

完整步骤、演练模式和冒烟清单见 `forward_authentication_service/fas-lark/README.md`。

### English

The level-1 FAS under `forward_authentication_service/fas-lark/` asks for a Feishu/Lark identity, sends a one-time code in the bot chat, and on success serves the same auth form as `fas-hid.php`: `tok` is `sha256(hid + faskey)` posted to `http://<gatewayaddress>/opennds_auth/`. Default ThemeSpec scripts are unchanged. Set `fas_secure_enabled` to `1`, keep `OPENNDS_FASKEY` identical to `option faskey`, and use `https://open.feishu.cn` or `https://open.larksuite.com`. App credentials, the verification token, and the encrypt key are environment variables. The operational guide and smoke checklist are in `forward_authentication_service/fas-lark/README.md`.

---


