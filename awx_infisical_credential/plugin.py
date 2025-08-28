# SPDX-License-Identifier: MIT
# Minimal AWX Credential Plugin for Infisical

from typing import Any, Dict
import os
import json
import requests

from awx_plugins.credentials.plugin import CredentialPlugin, CertFiles, raise_for_status

# inputs: то, что хранится в экземпляре "Infisical Credential" (конфиденты)
INPUTS = {
    "fields": [
        {
            "id": "url",
            "label": "Infisical API URL",
            "type": "string",
            "format": "url",
            "default": "https://app.infisical.com",
            "help_text": "Базовый URL Infisical (SaaS или ваш self-hosted).",
        },
        {
            "id": "token",
            "label": "Service Token / Personal Token",
            "type": "string",
            "secret": True,
            "help_text": "Bearer-токен для доступа к Infisical API.",
        },
        {
            "id": "tls_verify",
            "label": "Verify TLS",
            "type": "boolean",
            "default": True,
            "help_text": "Отключайте только для отладки/self-signed.",
        },
        {
            "id": "ca_cert",
            "label": "Custom CA certificate (PEM)",
            "type": "string",
            "multiline": True,
            "help_text": "Необязательно. PEM цепочка CA для верификации.",
        },
    ],
    # metadata: то, что указываете при линковке *в поле* другого credential’а
    "metadata": [
        {
            "id": "workspace_id",
            "label": "Workspace (Project) ID",
            "type": "string",
            "help_text": "ID проекта/воркспейса в Infisical (workspaceId).",
        },
        {
            "id": "environment",
            "label": "Environment",
            "type": "string",
            "help_text": "Напр. prod, dev, staging.",
        },
        {
            "id": "secret_path",
            "label": "Secret Path",
            "type": "string",
            "default": "/",
            "help_text": "Путь в дереве секретов, напр. /backend/api.",
        },
        {
            "id": "secret_name",
            "label": "Secret Name",
            "type": "string",
            "help_text": "Ключ секрета (имя переменной).",
        },
        {
            "id": "secret_version",
            "label": "Secret Version (optional)",
            "type": "string",
            "help_text": "Если нужно получить конкретную версию.",
        },
    ],
    "required": ["token"]
}

def _session(tls_verify: bool, ca_pem: str | None) -> requests.Session:
    s = requests.Session()
    if ca_pem:
        # Временно кладём CA в файл, как делают другие плагины через CertFiles
        with CertFiles(cert=None, key=None) as tmp:
            # CertFiles даёт tmpdir; сохраним там ca.pem
            capath = os.path.join(tmp, "ca.pem")
            with open(capath, "w", encoding="utf-8") as f:
                f.write(ca_pem)
            s.verify = capath
            return s
    s.verify = bool(tls_verify)
    return s

def _fetch_secret_raw(
    *,
    base_url: str,
    token: str,
    workspace_id: str | None,
    environment: str | None,
    secret_path: str | None,
    secret_name: str,
    secret_version: str | None,
    verify: bool,
    ca_pem: str | None,
) -> str:
    """
    Infisical RAW secret:
      GET {base_url}/api/v3/secrets/raw/{secretName}?workspaceId=...&environment=...&secretPath=...&secretVersion=...
    Returns JSON with secret value (field name differs по версиям API).
    """
    if not base_url.endswith("/"):
        base_url += "/"

    url = f"{base_url}api/v3/secrets/raw/{secret_name}"
    params: Dict[str, Any] = {}
    if workspace_id:
        params["workspaceId"] = workspace_id
    if environment:
        params["environment"] = environment
    if secret_path:
        params["secretPath"] = secret_path
    if secret_version:
        params["secretVersion"] = secret_version

    sess = _session(verify, ca_pem)
    headers = {"Authorization": f"Bearer {token}"}

    resp = sess.get(url, headers=headers, params=params, timeout=20)
    raise_for_status(resp)

    data = resp.json()
    # Возможные варианты по API (встречаются оба — подстрахуемся):
    # 1) {"secret": {"secretValue": "xxx", ...}}
    # 2) {"secretValue": "xxx", ...}
    if isinstance(data, dict):
        if "secret" in data and isinstance(data["secret"], dict):
            if "secretValue" in data["secret"]:
                return data["secret"]["secretValue"]
            if "value" in data["secret"]:
                return data["secret"]["value"]
        if "secretValue" in data:
            return data["secretValue"]
        if "value" in data:
            return data["value"]

    # На всякий — вернём raw JSON для дебага
    raise RuntimeError(f"Unexpected Infisical response: {json.dumps(data)[:500]}")

def backend(**kwargs):
    """
    Backend вызывается AWX, когда нужно подставить секрет в целевое поле.
    Возвращаем *строку* (значение секрета) — AWX подставит её в связанное поле.
    """
    # поля из inputs:
    base_url = kwargs.get("url") or "https://app.infisical.com"
    token = kwargs["token"]
    tls_verify = kwargs.get("tls_verify", True)
    ca_cert = kwargs.get("ca_cert")

    # metadata для конкретного lookup:
    workspace_id = kwargs.get("workspace_id")
    environment = kwargs.get("environment")
    secret_path = kwargs.get("secret_path") or "/"
    secret_name = kwargs["secret_name"]
    secret_version = kwargs.get("secret_version")

    value = _fetch_secret_raw(
        base_url=base_url,
        token=token,
        workspace_id=workspace_id,
        environment=environment,
        secret_path=secret_path,
        secret_name=secret_name,
        secret_version=secret_version,
        verify=bool(tls_verify),
        ca_pem=ca_cert,
    )
    # В credential plugins можно вернуть строку (частый кейс для single-value)
    # или dict. Для lookup поля нужен именно single-value -> возвращаем строку.
    return value

# Экспортируем плагин как entry point target
plugin = CredentialPlugin(
    name="Infisical Secret Lookup",
    inputs=INPUTS,
    backend=backend,
)
