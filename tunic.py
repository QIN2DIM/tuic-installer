# -*- coding: utf-8 -*-
# Time       : 2023/6/26 11:05
# Author     : QIN2DIM
# Github     : https://github.com/QIN2DIM
# Description:
from __future__ import annotations

import argparse
import getpass
import inspect
import json
import logging
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Literal, List, Any
from urllib import request
from urllib.request import urlretrieve
from uuid import uuid4

logging.basicConfig(
    level=logging.INFO, stream=sys.stdout, format="%(asctime)s - %(levelname)s - %(message)s"
)

if not sys.platform.startswith("linux"):
    logging.error(" Opps~ 你只能在 Linux 操作系统上运行该脚本")
    sys.exit()
if getpass.getuser() != "root":
    logging.error(" Opps~ 你需要手动切换到 root 用户运行该脚本")
    sys.exit()

URL = "https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-x86_64-unknown-linux-gnu"
LISTEN_PORT = 46676
host_ip = ""

TEMPLATE_SERVICE = """
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory={working_directory}
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart={exec_start}
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"""

TEMPLATE_PRINT_NEKORAY = """
====== ↓↓ 查看 NekoRay 配置文件 ↓↓ ======

cat {path_to_nekoray_config}

====== ↑↑ 查看 NekoRay 配置文件 ↑↑ ======

====== ↓↓ 在 NekoRay 中添加 tuic 节点 ↓↓ ======

{nekoray_config}

====== ↑↑ 在 NekoRay 中添加 tuic 节点 ↑↑ ======
"""


@dataclass
class Project:
    workstation = Path("/home/tuic-server")
    tuic_executable = workstation.joinpath("tuic")
    server_config = workstation.joinpath("server_config.json")

    client_nekoray_config = workstation.joinpath("nekoray_config.json")

    tuic_service = Path("/etc/systemd/system/tuic.service")

    def __post_init__(self):
        os.makedirs(self.workstation, exist_ok=True)


@dataclass
class Certificate:
    domain: str

    @property
    def fullchain(self):
        return f"/etc/letsencrypt/live/{self.domain}/fullchain.pem"

    @property
    def privkey(self):
        return f"/etc/letsencrypt/live/{self.domain}/privkey.pem"


@dataclass
class User:
    username: str
    password: str

    @classmethod
    def gen(cls):
        return cls(username=str(uuid4()), password=secrets.token_hex()[:16])


@dataclass
class ServerConfig:
    """
    Config template of tuic-server(v1.0.0)
    https://github.com/EAimTY/tuic/tree/dev/tuic-server
    """

    """
    The socket address to listen on
    """
    server: str

    """
    User map, contains user UUID and password
    """
    users: Dict[str, str]

    """
    The path to the private key file and cert file
    """
    certificate: str
    private_key: str

    """
    [Optional] Congestion control algorithm
    Default: "cubic"
    """
    congestion_control: Literal["cubic", "new_reno", "bbr"] = "bbr"

    """
    # [Optional] Application layer protocol negotiation
    # Default being empty (no ALPN)
    """
    alpn: List[str] | None = field(default_factory=list)

    """
    # Optional. If the server should create separate UDP sockets for relaying IPv6 UDP packets
    # Default: true
    """
    udp_relay_ipv6: bool = True

    """
    # Optional. Enable 0-RTT QUIC connection handshake on the server side
    # This is not impacting much on the performance, as the protocol is fully multiplexed
    # WARNING: Disabling this is highly recommended, as it is vulnerable to replay attacks. See https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones
    # Default: false
    """
    zero_rtt_handshake: bool = False

    """
    [Optional] Set if the listening socket should be dual-stack
    If this option is not set, the socket behavior is platform dependent
    """
    dual_stack: bool | None = None

    """
    [Optional] How long the server should wait for the client to send the authentication command
    Default: 3s
    """
    auth_timeout: str = "3s"

    """
    [Optional] Maximum duration server expects for task negotiation
    Default: 3s
    """
    task_negotiation_timeout: str = "3s"

    """
    [Optional] How long the server should wait before closing an idle connection
    Default: 10s
    """
    max_idle_time: str = "10s"

    """
    [Optional] Maximum packet size the server can receive from outbound UDP sockets, in bytes
    Default: 1500
    """
    max_external_packet_size: int = 1500

    """
    [Optional] Maximum number of bytes to transmit to a peer without acknowledgment
    Should be set to at least the expected connection latency multiplied by the maximum desired throughput
    Default: 8MiB * 2
    """
    send_window: int = 16777216

    """
    [Optional]. Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming blocked
    Should be set to at least the expected connection latency multiplied by the maximum desired throughput
    Default: 8MiB
    """
    receive_window: int = 8388608

    """
    [Optional] Interval between UDP packet fragment garbage collection
    Default: 3s
    """
    gc_interval: str = "3s"

    """
    [Optional] How long the server should keep a UDP packet fragment. Outdated fragments will be dropped
    Default: 15s
    """
    gc_lifetime: str = "15s"

    """
    [Optional] Set the log level
    Default: "warn"
    """
    log_level: Literal["warn", "info", "debug", "error"] = "warn"

    def __post_init__(self):
        self.server = self.server or "[::]:443"
        self.alpn = self.alpn or ["h3", "spdy/3.1"]

    @classmethod
    def from_json(cls, fp: Path):
        return from_dict_to_dataclass(cls, json.loads(fp.read_text(encoding="utf8")))

    @classmethod
    def from_automation(
        cls,
        users: List[User] | User,
        path_fullchain: str,
        path_privkey: str,
        server: str | None = f"[::]:{LISTEN_PORT}",
    ):
        if not isinstance(users, list):
            users = [users]
        users = {user.username: user.password for user in users}
        return cls(server=server, users=users, certificate=path_fullchain, private_key=path_privkey)

    def to_json(self, save_path):
        with open(save_path, "w", encoding="utf8") as file:
            json.dump(self.__dict__, file, indent=4, ensure_ascii=True)
        logging.info(f"保存服务端配置文件 - {save_path=}")


@dataclass
class ClientRelay:
    """Settings for the outbound TUIC proxy"""

    """
    // Format: "HOST:PORT"
    // The HOST must be a common name in the certificate
    // If the "ip" field in the "relay" section is not set, the HOST is also used for DNS resolving
    """
    server: str

    """
    TUIC User Object
    """
    uuid: str
    password: str

    """
    // Optional. The IP address of the TUIC proxy server, for overriding DNS resolving
    // If not set, the HOST in the "server" field is used for DNS resolving
    """
    ip: str | None = None

    """
    // Optional. Set the UDP packet relay mode
    // Can be:
    // - "native": native UDP characteristics
    // - "quic": lossless UDP relay using QUIC streams, additional overhead is introduced
    // Default: "native"
    """
    udp_relay_mode: Literal["native", "quic"] = "native"

    """
    // Optional. Congestion control algorithm, available options:
    // "cubic", "new_reno", "bbr"
    // Default: "cubic"
    """
    congestion_control: Literal["cubic", "new_reno", "bbr"] = "bbr"

    """
    // Optional. Application layer protocol negotiation
    // Default being empty (no ALPN)
    """
    alpn: List[str] | None = field(default_factory=list)

    """
    [Optional] Maximum number of bytes to transmit to a peer without acknowledgment
    Should be set to at least the expected connection latency multiplied by the maximum desired throughput
    Default: 8MiB * 2
    """
    send_window: int = 16777216

    """
    [Optional]. Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming blocked
    Should be set to at least the expected connection latency multiplied by the maximum desired throughput
    Default: 8MiB
    """
    receive_window: int = 8388608

    """
    [Optional] Interval between UDP packet fragment garbage collection
    Default: 3s
    """
    gc_interval: str = "3s"

    """
    [Optional] How long the server should keep a UDP packet fragment. Outdated fragments will be dropped
    Default: 15s
    """
    gc_lifetime: str = "15s"

    def __post_init__(self):
        self.alpn = self.alpn or ["h3", "spdy/3.1"]

    @classmethod
    def copy_from_server(cls, domain: str, user: User, sc: ServerConfig):
        server = f"{domain}:{LISTEN_PORT}"
        return cls(
            server=server,
            uuid=user.username,
            password=user.password,
            alpn=sc.alpn,
            congestion_control=sc.congestion_control,
            send_window=sc.send_window,
            receive_window=sc.receive_window,
            gc_interval=sc.gc_interval,
            gc_lifetime=sc.gc_lifetime,
        )


@dataclass
class ClientLocal:
    server: str
    username: str | None = None
    password: str | None = None
    dual_stack: bool | None = None
    max_packet_size: int | None = 1500


@dataclass
class ClientConfig:
    """
    https://github.com/EAimTY/tuic/tree/dev/tuic-client
    Config template of tuic-client(v1.0.0)
    Apply on the NekoRay(v3.8)
    """

    relay: Dict[str, Any] = field(default_factory=dict)
    local: Dict[str, Any] = field(default_factory=dict)
    log_level: Literal["warn", "info", "debug", "error"] = "warn"

    @classmethod
    def gen_for_nekoray(cls, relay: ClientRelay, server_addr: str, server_ip: str | None = None):
        """

        :param relay:
        :param server_addr: 服务器域名
        :param server_ip: 服务器IP
        :return:
        """
        local = ClientLocal(server="127.0.0.1:%socks_port%")

        relay.server = f"{server_addr}:{LISTEN_PORT}"

        if server_ip is not None:
            relay.ip = server_ip

        relay, local = relay.__dict__, local.__dict__

        local = {k: local[k] for k in local if local[k] is not None}
        relay = {k: relay[k] for k in relay if relay[k] is not None}

        return cls(relay=relay, local=local)

    def to_json(self, save_path):
        with open(save_path, "w", encoding="utf8") as file:
            json.dump(self.__dict__, file, indent=4, ensure_ascii=True)
        logging.info(f"保存服务端配置文件 - {save_path=}")


@dataclass
class TuicService:
    path: str
    name: str = "tuic"

    @classmethod
    def build_from_template(cls, path: Path, template: str | None = ""):
        template = template.format()
        path.write_text(template, encoding="utf8")
        os.system("systemctl daemon-reload")
        return cls(path=f"{path}")

    def download_tuic_server(self, save_path: Path):
        save_path_ = str(save_path)
        try:
            urlretrieve(URL, f"{save_path_}")
            logging.info(f"下载完毕 - {save_path_=}")
        except OSError:
            logging.info("服务正忙，尝试停止任务...")
            self.stop()
            time.sleep(0.5)
            return self.download_tuic_server(save_path)
        else:
            os.system(f"chmod +x {save_path_}")
            logging.info(f"授予执行权限 - {save_path_=}")

    def start(self):
        os.system(f"systemctl enable --now {self.name}")
        logging.info("系统服务已启动")
        logging.info("已设置服务开机自启")

    def stop(self):
        logging.info("停止系统服务")
        os.system(f"systemctl stop {self.name}")

    def status(self):
        result = subprocess.run(
            f"systemctl is-active {self.name}".split(), capture_output=True, text=True
        )
        logging.info(f"服务状态 - TUIC service status: {result.stdout.strip()}")

    def remove(self, workstation: Path):
        logging.info("注销系统服务")
        os.system(f"systemctl disable --now {self.name} > /dev/null 2>&1")

        logging.info("关停相关进程")
        os.system("pkill tuic")

        logging.info("移除系统服务配置文件")
        os.remove(self.path)

        logging.info("移除工作空间")
        shutil.rmtree(workstation)


class CertBot:
    def __init__(self, domain: str):
        self._domain = domain

    def run(self):
        logging.info("移除證書殘影...")
        p = Path("/etc/letsencrypt/live/")
        for k in os.listdir(p):
            k_full = p.joinpath(k)
            if (
                not p.joinpath(self._domain).exists()
                and k.startswith(f"{self._domain}-")
                and k_full.is_dir()
            ):
                shutil.rmtree(k_full, ignore_errors=True)

        logging.info("正在为解析到本机的域名申请免费证书")
        os.system("apt install certbot -y > /dev/null 2>&1")
        os.system("systemctl stop nginx > /dev/null 2>&1 && nginx -s stop")
        p = subprocess.Popen(
            f"certbot certonly --standalone --register-unsafely-without-email -d {self._domain}".split(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        p.stdin.write("y\n")
        p.stdin.flush()
        output = p.stderr.read().strip()
        if output and "168 hours" in output:
            logging.warning(
                """
                一个域名每168小时只能申请5次免费证书，
                你可以为当前主机创建一条新的域名A纪录来解决这个问题。
                在解决这个问题之前你没有必要进入到后续的安装步骤。
                """
            )
            sys.exit()

    def remove(self):
        """可能存在重复申请的 domain-0001"""
        logging.info("移除可能残留的证书文件")
        p = subprocess.Popen(
            f"certbot delete --cert-name {self._domain}".split(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        p.stdin.write("y\n")
        p.stdin.flush()

        # 兜底
        shutil.rmtree(Path(Certificate(self._domain).fullchain).parent, ignore_errors=True)


def from_dict_to_dataclass(cls, data):
    return cls(
        **{
            key: (data[key] if val.default == val.empty else data.get(key, val.default))
            for key, val in inspect.signature(cls).parameters.items()
        }
    )


def check_my_hostname(domain: str):
    global host_ip
    try:
        host_ip = socket.getaddrinfo(domain, None)[-1][4][0]
    except socket.gaierror:
        logging.error(f"域名不可达或拼写错误的域名 - {domain=}")
        return False

    my_ip = request.urlopen("http://ifconfig.me/ip").read().decode("utf8")
    if my_ip != host_ip:
        logging.error(f"你的主机外网IP与域名解析到的IP不一致 - {my_ip=} {domain=} {host_ip=}")
        return False
    return True


class Scaffold:
    @staticmethod
    def install(params: argparse.Namespace):
        """
        1. 运行 certbot 申请证书
        3. 初始化 Project 环境对象
        4. 初始化 server config
        5. 初始化 client config
        6. 生成 nekoray tuic config 配置信息
        :param params:
        :return:
        """
        domain = params.domain
        if not domain:
            domain = input("> 解析到本机的域名：")

        # 检查域名是否可达
        # 检查域名指向的IP是否为本机公网IP
        if not check_my_hostname(domain):
            return
        logging.info(f"域名解析成功 - {domain=}")

        # 初始化证书对象
        cert = Certificate(domain)

        # 为绑定到本机的域名申请证书
        if not Path(cert.fullchain).exists():
            CertBot(domain).run()
        else:
            logging.info("证书文件已存在")

        # 初始化 workstation
        project = Project()

        # 初始化系统服务配置
        template = TEMPLATE_SERVICE.format(
            exec_start=f"{project.tuic_executable} -c {project.server_config}",
            working_directory=f"{project.workstation}",
        )
        tuic = TuicService.build_from_template(path=project.tuic_service, template=template)

        logging.info("正在生成默认的服务端配置")
        user = User.gen()
        server_config = ServerConfig.from_automation(user, cert.fullchain, cert.privkey)
        server_config.to_json(save_path=str(project.server_config))

        logging.info("正在生成对应的 NekoRay 客户端配置")
        relay = ClientRelay.copy_from_server(domain, user, server_config)
        client_config = ClientConfig.gen_for_nekoray(relay, server_addr=domain, server_ip=host_ip)
        client_config.to_json(save_path=str(project.client_nekoray_config))

        logging.info(f"正在下载 tuic-server")
        tuic.download_tuic_server(save_path=project.tuic_executable)

        logging.info("正在部署系统服务")
        tuic.start()
        tuic.status()

        # 在控制台输出客户端配置
        logging.info(
            TEMPLATE_PRINT_NEKORAY.format(
                nekoray_config=json.dumps(client_config.__dict__, indent=4),
                path_to_nekoray_config=str(project.client_nekoray_config),
            )
        )

    @staticmethod
    def remove(params: argparse.Namespace):
        domain = params.domain
        if not domain:
            domain = input("> 解析到本机的域名：")
        if not check_my_hostname(domain):
            return
        logging.info(f"解绑服务 - bind={domain}")

        project = Project()

        # 移除可能残留的证书文件
        CertBot(domain).remove()

        # 关停进程，注销系统服务，移除工作空间
        TuicService.build_from_template(project.tuic_service).remove(project.workstation)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TUIC Scaffold (Python3.8+)")
    subparsers = parser.add_subparsers(dest="command")

    install_parser = subparsers.add_parser("install", help="安装并自动运行 tuic-server")
    install_parser.add_argument("-d", "--domain", type=str, help="传参指定域名，否则需要在运行脚本后以交互的形式输入")

    remove_parser = subparsers.add_parser("remove", help="移除绑定到指定域名的 tuic-server")
    remove_parser.add_argument("-d", "--domain", type=str, help="传参指定域名，否则需要在运行脚本后以交互的形式输入")

    args = parser.parse_args()
    command = args.command

    with suppress(KeyboardInterrupt):
        if command == "install":
            Scaffold.install(params=args)
        elif command == "remove":
            Scaffold.remove(params=args)
        else:
            parser.print_help()
