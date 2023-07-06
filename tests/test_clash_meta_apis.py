# -*- coding: utf-8 -*-
# Time       : 2023/7/7 3:42
# Author     : QIN2DIM
# Github     : https://github.com/QIN2DIM
# Description:
from __future__ import annotations

import json
import socket
from urllib.parse import urlparse

from loguru import logger

from scaffold.clash_meta_apis import ClashMetaAPI
from scaffold.toolbox import project, init_log

# 快速生成密钥，添加到 Clash-Verge 外部控制组件
# python -c "import secrets;print(secrets.token_hex()[:16])"
CONTROLLER_SECRET = ""
CONTROLLER_URL = "http://127.0.0.1:9090"

init_log(
    stdout_level="INFO",
    error=project.logs.joinpath("error.log"),
    runtime=project.logs.joinpath("runtime.log"),
    serialize=project.logs.joinpath("serialize.log"),
)

clash = ClashMetaAPI.from_secret(CONTROLLER_SECRET, CONTROLLER_URL, project.database)


def test_is_live():
    u = urlparse(CONTROLLER_URL)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            host, port = u.netloc.split(":")
            s.bind((host, int(port)))
            raise OSError
    except socket.gaierror:
        logger.debug("外部控制接口已关闭", netloc=u.netloc, port=u.port)
        return False
    except OSError:
        logger.debug("外部控制接口可达", netloc=u.netloc)
        return True


def test_get_dns_query():
    clash.flush_fakeip_cache()
    names = ["www.bilibili.com", "www.baidu.com", "www.google.com", "www.youtube.com"]
    for name in names:
        r = clash.get_dns_query(name=name, dns_type="A")
        fp = clash.db.joinpath(f"dns_query_{name}.json")
        fp.write_text(json.dumps(r, indent=4))
        logger.debug("TEST - DNS Query", name=name, result=r)


def test_get_connections():
    conns = clash.get_connections()
    fp = clash.db.joinpath("connections.json")
    fp.write_text(json.dumps(conns, indent=4))
    logger.debug("TEST - Get Connections", conns=conns)
