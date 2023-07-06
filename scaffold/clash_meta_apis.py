# -*- coding: utf-8 -*-
# Time       : 2023/7/7 3:10
# Author     : QIN2DIM
# Github     : https://github.com/QIN2DIM
# Description:
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Literal, Any

import requests
from loguru import logger
from requests.sessions import Session


@dataclass
class ClashMetaAPI:
    secret: str
    controller_url: str
    db: Path

    _session: Session = None

    @classmethod
    def from_secret(
        cls, secret: str, controller_url: str | None = None, path_db: Path | None = None
    ) -> ClashMetaAPI | None:
        _url = controller_url or "http://127.0.0.1:9090"
        db = path_db or Path("database")
        if not secret:
            logger.warning("请设置你的外部控制密钥", documentation="https://wiki.metacubex.one/api/#_1")
        instance = cls(secret=secret, controller_url=_url, db=db)
        instance._session = requests.session()
        return instance

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.secret}"}

    def get_version(self) -> Dict[str, Any]:
        api = f"{self.controller_url}/version"
        return requests.get(api, headers=self.headers).json()

    def get_dns_query(
        self, name: str, dns_type: Literal["A", "CNAME", "MX"] | None = ""
    ) -> Dict[str, Any]:
        api = f"{self.controller_url}/dns/query"
        params = {"name": name}
        if dns_type:
            params["type"] = dns_type
        return self._session.get(api, headers=self.headers, params=params).json()

    def get_proxies(self):
        api = f"{self.controller_url}/proxies"
        return self._session.get(api, headers=self.headers).json()

    def get_traffic(self):
        api = f"{self.controller_url}/traffic"
        return self._session.get(api, headers=self.headers).json()

    def flush_fakeip_cache(self):
        api = f"{self.controller_url}/cache/fakeip/flush"
        self._session.post(api, headers=self.headers)

    def get_connections(self):
        api = f"{self.controller_url}/connections"
        return self._session.get(api, headers=self.headers).json()

    def delete_connection(self, conn_id: str | None = ""):
        api = f"{self.controller_url}/connections"
        if conn_id:
            api = f"{self.controller_url}/connections/:{conn_id}"
        self._session.delete(api, headers=self.headers)
