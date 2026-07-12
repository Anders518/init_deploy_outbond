from __future__ import annotations

from typing import Any


def render_sub2api_compose(cfg: dict[str, Any]) -> str:
    publish = ''
    if bool(cfg.get('publish_port', False)):
        publish = f'    ports:\n      - "127.0.0.1:{int(cfg.get("published_port", 8080))}:8080"\n'
    return f'''services:
  sub2api:
    image: ${{SUB2API_IMAGE}}
    container_name: sub2api
    restart: unless-stopped
    ulimits:
      nofile:
        soft: 100000
        hard: 100000
{publish}    volumes:
      - ./data:/app/data
    environment:
      AUTO_SETUP: "true"
      SERVER_HOST: 0.0.0.0
      SERVER_PORT: "8080"
      SERVER_MODE: release
      DATABASE_HOST: postgres
      DATABASE_PORT: "5432"
      DATABASE_USER: ${{POSTGRES_USER}}
      DATABASE_PASSWORD: ${{POSTGRES_PASSWORD}}
      DATABASE_DBNAME: ${{POSTGRES_DB}}
      DATABASE_SSLMODE: disable
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      REDIS_PASSWORD: ${{REDIS_PASSWORD}}
      REDIS_DB: "0"
      ADMIN_EMAIL: ${{ADMIN_EMAIL}}
      ADMIN_PASSWORD: ${{ADMIN_PASSWORD}}
      JWT_SECRET: ${{JWT_SECRET}}
      TOTP_ENCRYPTION_KEY: ${{TOTP_ENCRYPTION_KEY}}
      TZ: ${{TZ}}
      SECURITY_URL_ALLOWLIST_ENABLED: "{str(bool(cfg.get('security_url_allowlist_enabled', True))).lower()}"
      SECURITY_URL_ALLOWLIST_ALLOW_INSECURE_HTTP: "{str(bool(cfg.get('allow_insecure_http', False))).lower()}"
      SECURITY_URL_ALLOWLIST_ALLOW_PRIVATE_HOSTS: "{str(bool(cfg.get('allow_private_hosts', False))).lower()}"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - internal
      - proxy
    healthcheck:
      test: ["CMD", "wget", "-q", "-T", "5", "-O", "/dev/null", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

  postgres:
    image: postgres:18-alpine
    container_name: sub2api-postgres
    restart: unless-stopped
    volumes:
      - ./postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: ${{POSTGRES_USER}}
      POSTGRES_PASSWORD: ${{POSTGRES_PASSWORD}}
      POSTGRES_DB: ${{POSTGRES_DB}}
      PGDATA: /var/lib/postgresql/data
      TZ: ${{TZ}}
    networks: [internal]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

  redis:
    image: redis:8-alpine
    container_name: sub2api-redis
    restart: unless-stopped
    volumes:
      - ./redis_data:/data
    command: ["sh", "-c", "redis-server --save 60 1 --appendonly yes --appendfsync everysec $${REDIS_PASSWORD:+--requirepass \"$${REDIS_PASSWORD}\"}"]
    environment:
      REDISCLI_AUTH: ${{REDIS_PASSWORD}}
      TZ: ${{TZ}}
    networks: [internal]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 5s

networks:
  internal:
    driver: bridge
  proxy:
    external: true
    name: ${{PROXY_NETWORK}}
'''
