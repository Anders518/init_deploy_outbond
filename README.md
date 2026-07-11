# init_deploy_outbond

用于 Debian/Ubuntu VPS 的 Python 部署工具，部署以下结构：

```text
公网 443/tcp
  └─ 3x-ui / Xray / VLESS Reality

公网 8443/tcp
  └─ Caddy
       ├─ 面板路径 → BasicAuth → 3x-ui:2053
       └─ /sub/*   → 3x-ui:2096
```

支持：

- Docker Compose bridge 网络
- Docker IPv6
- Cloudflare Proxy + Origin CA 长期证书
- 可选 Cloudflare DNS-01 ACME 模式
- 可选 SSH 端口修改与密钥登录加固
- 可选普通管理用户、Fail2Ban、自动安全更新和 sysctl 加固
- 部署前配置备份

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
- root 权限
- Docker；也可以由脚本自动安装
- Cloudflare 托管的域名

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
sudo python3 deploy.py deploy
```

查看状态：

```bash
sudo python3 deploy.py status
```

更新容器：

```bash
sudo python3 deploy.py update
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
sudo CLOUDFLARE_API_TOKEN='your-token' python3 deploy.py deploy
```

该模式会构建包含 `caddy-dns/cloudflare` 的自定义 Caddy 镜像。

## 端口规划

默认端口：

```text
443/tcp   VLESS Reality
8443/tcp  Cloudflare 到 Caddy 的 HTTPS 入口
2053/tcp  3x-ui 面板内部端口，不发布到宿主机
2096/tcp  订阅内部端口，不发布到宿主机
```

VPS 防火墙建议只开放：

```text
SSH 端口
443/tcp
8443/tcp
```

使用 Cloudflare Proxy 后，最好进一步把 `8443/tcp` 的来源限制为 Cloudflare IP 段，防止绕过 Cloudflare 直接访问源站。Cloudflare IP 段会变化，因此应通过独立维护流程定期同步，不建议在部署脚本中硬编码。

## 3x-ui 配置

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

Reality inbound：

```text
Protocol: VLESS
Port: 443
Network: TCP
Security: Reality
Flow: xtls-rprx-vision
Encryption/decryption: none
```

订阅路径默认不使用 Caddy BasicAuth，因为多数客户端更新订阅时无法处理交互式 BasicAuth。面板路径仍由 Caddy BasicAuth 和 3x-ui 自身认证双重保护。

## SSH 加固

加固默认关闭。建议分两次执行，避免锁死 SSH。

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
└── 3x-ui/
```

至少备份：

```text
/opt/proxy-stack/3x-ui/db
/opt/proxy-stack/caddy/data
/opt/proxy-stack/secrets
/opt/proxy-stack/Caddyfile
/opt/proxy-stack/docker-compose.yml
/opt/proxy-stack/.env
/etc/ssh
/etc/docker/daemon.json
```

备份必须加密，因为其中包含证书私钥、面板凭据和 3x-ui 数据库。
