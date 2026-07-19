# init_deploy_outbond

用于 Debian/Ubuntu VPS 的 Python 部署工具，部署以下结构：

```text
公网 443/tcp
  └─ 二选一：3x-ui / Xray，或 S-UI / sing-box / AnyTLS

公网 8443/tcp
  └─ Caddy
       ├─ 面板路径 → BasicAuth → 所选面板:2053
       └─ /sub/*   → 所选面板:2096
```

支持：

- Docker Compose bridge 网络
- Docker IPv6
- Cloudflare Proxy + Origin CA 长期证书
- 可选 Cloudflare DNS-01 ACME 模式
- 可选 SSH 端口修改与密钥登录加固
- 可选普通管理用户、UFW、Fail2Ban、自动安全更新和 sysctl 加固
- 部署前配置备份
- 3x-ui 与 S-UI（sing-box/AnyTLS）互斥选择
- 自动创建 VLESS Reality 或 AnyTLS 入站、用户和客户端配置
- 自动使用 Mihomo 与 sing-box 请求外部 HTTPS，并在后端重启后复测
- 自动检测和修复宿主机/Docker IPv6；验证失败时回滚并撤销托管 AAAA

## 节点面板二选一

`panel.backend` 决定唯一的节点管理面板。未配置时默认为 `3x-ui`，兼容旧配置：

```toml
[panel]
backend = "3x-ui" # 或 "s-ui"
```

选择 S-UI：

```toml
[panel]
backend = "s-ui"
path = "/"
subscription_path = "/sub"

[panel.sui]
username = "sui-admin"
password_mode = "environment"
password_env = "VPSDEPLOY_SUI_PASSWORD"
cli = "auto"
allow_default_credentials = false

[docker]
sui_image = "alireza7/s-ui:v1.5.3"
```

部署命令：

```bash
sudo env VPSDEPLOY_SUI_PASSWORD='use-a-strong-password' \
  CLOUDFLARE_API_TOKEN='your-token' \
  uv run --no-dev --frozen python deploy.py deploy
```

部署器只会生成所选面板的 Compose 服务，并通过 `--remove-orphans` 移除另一个面板容器，避免二者同时占用节点端口。原面板数据目录不会自动删除，便于回退。S-UI 启动后，部署器会通过其 CLI 固化管理员凭据、面板路径、面板内部端口和订阅端口，并在重启后校验持久化结果。

容器就绪后，`node-config` 会继续创建所选协议的 TLS/Reality 配置、入站和用户，不需要登录面板手工补节点：

- `3x-ui` 自动配置 VLESS Reality，并固定兼容的 Xray 版本。
- `s-ui` 自动让 Caddy 通过 DNS-01 获取节点证书，再配置 AnyTLS。

`node-verify` 会生成 root-only 的 Mihomo 与 sing-box 配置，分别通过节点请求外部 HTTPS，检查出口 IP 和服务端流量计数，然后重启所选面板并重复一次。任何必需客户端失败都会使部署命令返回非零。

```text
/opt/proxy-stack/state/node-client.json
/opt/proxy-stack/state/reality-client.json
/opt/proxy-stack/state/anytls-client.json
/opt/proxy-stack/state/mihomo-test.yaml
/opt/proxy-stack/state/sing-box-test.json
/opt/proxy-stack/state/node-verification.json
```

这些文件均为 `0600 root:root`。节点域名必须保持 DNS only。S-UI 的数据库和证书目录分别持久化到 `/opt/proxy-stack/s-ui/db` 与 `/opt/proxy-stack/s-ui/cert`。

## 修改自动生成的账号密码

`password_mode = "generate"` 表示首次随机生成、后续复用已有值，重复部署不会无故更换密码。查看当前值：

```bash
sudo uv run --no-dev --frozen python deploy.py credentials
```

推荐使用环境变量换成自定义密码，避免把明文写入 TOML。例如当前选择 3x-ui：

```toml
[panel]
basic_auth_password_mode = "environment"
basic_auth_password_env = "VPSDEPLOY_CADDY_PASSWORD"

[panel.xui]
username = "my-xui-user"
password_mode = "environment"
password_env = "VPSDEPLOY_XUI_PASSWORD"
```

```bash
sudo env \
  VPSDEPLOY_CADDY_PASSWORD='new-caddy-password' \
  VPSDEPLOY_XUI_PASSWORD='new-xui-password' \
  uv run --no-dev --frozen python deploy.py deploy --task certificate --task proxy-stack
```

选择 S-UI 时改用 `[panel.sui]` 和 `VPSDEPLOY_SUI_PASSWORD`。部署器会调用面板 CLI 更新凭据、重启容器，并验证新值已持久化。

也可以使用 `password_mode = "config"` 并填写 `password`，但必须执行 `chmod 600 config.toml`，且绝不能提交该文件。`prompt` 模式适合人工运行。

Sub2API 首次部署前可通过 `sub2api.admin_password_mode = "environment"` 和 `VPSDEPLOY_SUB2API_ADMIN_PASSWORD` 指定管理员密码。已有数据库的管理员密码应在 Sub2API 面板中修改；`ADMIN_PASSWORD` 是初始化凭据，不会强制覆盖现有管理员。PostgreSQL、JWT、TOTP 密钥不是普通登录密码，不能仅修改 TOML 后重启；这类密钥需要单独的数据迁移或轮换流程。

## 安全说明

不要提交以下内容：

- `config.toml`
- Cloudflare API Token
- Cloudflare Origin CA 私钥
- Reality 私钥、UUID、Short ID
- `/opt/proxy-stack/secrets.txt`

仓库已经通过 `.gitignore` 排除常见证书、密钥和运行配置文件。

## 环境要求

- Debian 或 Ubuntu
- Python 3.11+
- uv 0.11+
- root 权限
- Docker；也可以由脚本自动安装
- Cloudflare 托管的域名

初始化开发/测试环境：

```bash
uv sync --frozen
uv run --frozen pytest
```

部署命令使用 `--no-dev`，不会安装 pytest 等开发依赖。`uv.lock` 已提交，用于保证不同主机解析到一致的工具版本。

## 推荐 TLS 模式：Cloudflare Origin CA

访问链路：

```text
浏览器
  → Cloudflare 公网证书
  → Cloudflare Proxy
  → Cloudflare Origin CA 证书
  → Caddy:8443
```

该模式不需要：

- Cloudflare DNS API Token
- Caddy Cloudflare DNS 插件
- 自定义 Caddy 镜像
- ACME 自动签发和续期

注意：Cloudflare Origin CA 证书只用于 Cloudflare 到源站。直接访问 VPS 或将面板记录切换为 DNS only 时，浏览器不会信任该证书。

### Cloudflare 配置

面板域名：

```text
panel.example.net  A/AAAA  VPS 地址  Proxied（橙云）
```

SSL/TLS 模式设置为：

```text
Full (strict)
```

Reality 节点域名必须保持：

```text
node.example.net  A/AAAA  VPS 地址  DNS only
```

### 创建 Origin CA 证书

在 Cloudflare 控制台为面板域名创建 Origin CA 证书，将证书和私钥保存到 VPS：

```bash
sudo install -d -m 700 /root/cloudflare-origin
sudo nano /root/cloudflare-origin/origin.crt
sudo nano /root/cloudflare-origin/origin.key
sudo chmod 600 /root/cloudflare-origin/origin.key
```

配置：

```toml
[panel.tls]
mode = "cloudflare_origin"
certificate_file = "/root/cloudflare-origin/origin.crt"
private_key_file = "/root/cloudflare-origin/origin.key"

[docker]
caddy_image = "caddy:2-alpine"
```

部署时，脚本会把证书复制到：

```text
/opt/proxy-stack/secrets/cloudflare-origin.crt
/opt/proxy-stack/secrets/cloudflare-origin.key
```

私钥权限会设为 `0600`，并以只读方式挂载到 Caddy 容器。

## 快速部署

```bash
git clone https://github.com/Anders518/init_deploy_outbond.git
cd init_deploy_outbond
cp config.example.toml config.toml
nano config.toml
sudo uv run --no-dev --frozen python deploy.py deploy
```

交互式终端界面：

```bash
sudo uv run --no-dev --frozen python deploy.py tui
```

TUI 支持交互式生成核心配置、完整部署、VLESS/AnyTLS 切换、账号密码修改、节点凭据轮换、双内核验收、IPv6 检测/修复、系统加固配置部署、wg-easy 私有覆盖网络、Sub2API 配置部署、状态与凭据查看。系统加固向导可配置 SSH 双端口迁移、root/密码登录策略、UFW、Fail2Ban、自动安全更新、sysctl 与 Apport。向导先使用临时 `0600` 配置完成部署验收，成功后才原子更新主配置；密码通过临时环境变量传给子进程，不写入主配置。

## IPv6 自动修复与回退

`ipv6-connectivity` 任务会：

1. 选择稳定的全局 IPv6 地址并验证宿主机 HTTPS 出口。
2. 创建临时 IPv6 Docker 网络，通过一次性 curl 容器验证真实出口。
3. 失败时尝试启用 IPv6、转发以及物理接口 `accept_ra=2`，必要时安全合并 Docker daemon 配置。
4. 修改前保存文件和运行时 sysctl 值；修复后必须再次通过宿主机和 Docker 测试。
5. 任一步失败就恢复原文件、sysctl 和 Docker 状态，继续 IPv4-only 部署。
6. DNS 阶段仅在验证成功后发布 AAAA；回退时删除带有本项目管理标记的 AAAA，不碰用户手工记录。

结果保存在 `/opt/proxy-stack/state/ipv6.json`，权限为 `0600 root:root`。

查看状态：

```bash
sudo uv run --no-dev --frozen python deploy.py status
```

更新容器：

```bash
sudo uv run --no-dev --frozen python deploy.py update
```

## 可选 DNS-01 模式

需要浏览器直接访问源站，或者不希望依赖 Cloudflare Proxy 时，可以使用：

```toml
[panel.tls]
mode = "acme_dns"

[docker]
caddy_image = "local/caddy-cloudflare:latest"
```

运行：

```bash
sudo env CLOUDFLARE_API_TOKEN='your-token' uv run --no-dev --frozen python deploy.py deploy
```

该模式会构建包含 `caddy-dns/cloudflare` 的自定义 Caddy 镜像。

无人值守部署也可将 token 单独保存为 `0600` 文件：

```toml
[cloudflare]
api_token_file = "cloudflare.secret"

[dns]
api_token_file = "cloudflare.secret"
```

## 端口规划

默认端口：

```text
443/tcp   VLESS Reality 或 AnyTLS（由 panel.backend 决定）
8443/tcp  Cloudflare 到 Caddy 的 HTTPS 入口
2053/tcp  所选面板内部端口，不发布到宿主机
2096/tcp  订阅内部端口，不发布到宿主机
```

VPS 防火墙建议只开放：

```text
SSH 端口
443/tcp
8443/tcp
```

使用 Cloudflare Proxy 后，最好进一步把 `8443/tcp` 的来源限制为 Cloudflare IP 段，防止绕过 Cloudflare 直接访问源站。Cloudflare IP 段会变化，因此应通过独立维护流程定期同步，不建议在部署脚本中硬编码。

## 自动节点配置

面板：

```text
Listen IP: 留空或 0.0.0.0
Listen port: 2053
URI path: 与 panel.path 一致
```

订阅：

```text
Listen IP: 留空或 0.0.0.0
Internal port: 2096
URI path: 与 panel.subscription_path 一致
External scheme: https
External domain: 面板域名
External port: 8443
```

选择 3x-ui 时自动生成：

```text
Protocol: VLESS
Port: 443
Network: TCP
Security: Reality
Flow: xtls-rprx-vision
Encryption/decryption: none
```

选择 S-UI 时自动生成：

```text
Protocol: AnyTLS
Port: 443
TLS certificate: Caddy DNS-01 / Let's Encrypt
SNI: domains.node
User password: root-only node state
```

订阅路径默认不使用 Caddy BasicAuth，因为多数客户端更新订阅时无法处理交互式 BasicAuth。面板路径仍由 Caddy BasicAuth 和 3x-ui 自身认证双重保护。

## wg-easy 私有覆盖网络

`wg_easy.enabled = true` 会部署官方 `ghcr.io/wg-easy/wg-easy:15`。WireGuard UDP 端口不会映射到宿主机，云防火墙和 UFW 也不会放行它；容器仅在 `proxy_stack` Docker 网络获得固定私网 endpoint。组件主机必须同时运行 Mihomo TUN 与 WireGuard，将该 endpoint 的 UDP 流量经 AnyTLS 节点转发。

部署器生成两个 root-only 客户端文件：

- `/opt/wg-easy/state/mihomo-wg-gateway.yaml`：完整严格配置，AnyTLS 强制 `udp: true`，最终规则不含 `DIRECT`。
- `/opt/wg-easy/state/mihomo-route.yaml`：合并到现有 Mihomo 配置的路由片段。

wg-easy Web UI 只绑定 `127.0.0.1:51821`，通过 SSH 转发访问：

```bash
ssh -p 4522 -L 51821:127.0.0.1:51821 deploy@SERVER
```

然后打开 `http://127.0.0.1:51821`。使用 `credentials` 命令查看管理员凭据与私网 endpoint。移动平台通常无法同时运行两个 VPN/TUN 服务，因此该模式主要面向 Linux、Windows、macOS 与支持策略路由的路由器。

## SSH 加固

加固默认关闭。建议分两次执行，避免锁死 SSH。

UFW 同样默认关闭，优先使用云服务商的防火墙或安全组。确需主机防火墙时，在 `[hardening] enabled = true` 的基础上设置：

```toml
[hardening.ufw]
enabled = true
default_incoming = "deny"
default_outgoing = "allow"
logging = true
logging_level = "low"
```

部署器会在启用 UFW 前先放行当前/新 SSH 端口、节点端口和面板/订阅端口。Docker 公开端口仍受 Docker iptables 规则影响，因此不应把 UFW 当作云防火墙的替代品。

所有加固任务均使用自动回退生命周期。SSH、UFW、Fail2Ban、自动更新或 sysctl 在应用或后置验证阶段失败时，会恢复变更前的配置文件、服务启用/运行状态及相关运行时设置。SSH 回退还会恢复账号数据库、sudoers、authorized_keys 和原监听配置；若回退本身失败，部署器会同时报告原始错误与回退错误，不会把部分成功误报为完成。

首次：

```toml
[hardening]
enabled = true

[hardening.ssh]
enabled = true
current_port = 4522
new_port = 62222
create_admin_user = true
admin_user = "deploy"
disable_root_login = false
disable_password_auth = true
allow_users = ["root", "deploy"]
```

先在云厂商防火墙放行新端口，并保持当前 SSH 会话。部署后测试：

```bash
ssh -p 62222 deploy@SERVER
sudo whoami
```

确认成功后再设置：

```toml
disable_root_login = true
allow_users = ["deploy"]
```

重新执行部署并再次测试，最后删除旧 SSH 端口的防火墙规则。

## Docker IPv6

```toml
[docker]
enable_ipv6 = true
ipv6_subnet = ""
```

空子网表示让 Docker 自动选择可用网段。如果当前 Docker 版本要求显式子网，可设置一个未使用的 ULA `/64`。

宿主机 IPv6 正常不代表容器 IPv6 一定正常。可检查：

```bash
docker exec 3x-ui ip -6 addr
docker exec 3x-ui ip -6 route
docker exec 3x-ui curl -6 https://api64.ipify.org
```

选择 S-UI 时，将以上容器名替换为 `s-ui`。

## 生成目录

```text
/opt/proxy-stack/
├── .env
├── Caddyfile
├── docker-compose.yml
├── secrets.txt
├── secrets/
│   ├── cloudflare-origin.crt
│   └── cloudflare-origin.key
├── backups/
├── caddy/
├── 3x-ui/             # 选择 3x-ui 时使用
├── s-ui/              # 选择 S-UI 时使用
└── state/             # 客户端配置和验证报告（0600）
```

至少备份：

```text
/opt/proxy-stack/3x-ui/db
/opt/proxy-stack/s-ui/db
/opt/proxy-stack/caddy/data
/opt/proxy-stack/secrets
/opt/proxy-stack/Caddyfile
/opt/proxy-stack/docker-compose.yml
/opt/proxy-stack/.env
/etc/ssh
/etc/docker/daemon.json
```

备份必须加密，因为其中包含证书私钥、面板凭据和 3x-ui 数据库。
