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
from typing import Dict, Literal, List, Any, NoReturn, Union, Tuple
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

TEMPLATE_META_CONFIG = """
mixed-port: 7890
allow-lan: true
bind-address: '*'
geodata-mode: true
global-client-fingerprint: random
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'
dns:
  enable: true
  prefer-h3: true
  listen: 0.0.0.0:53
  ipv6: true
  default-nameserver: [ 223.5.5.5, 8.8.8.8 ]
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  nameserver: [ 'https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query', "quic://dns.adguard.com:784", "tls://223.5.5.5:853"]
  fallback: [ 'https://8.8.8.8/dns-query', 'https://doh.dns.sb/dns-query', 'https://dns.cloudflare.com/dns-query', 'https://dns.twnic.tw/dns-query']
  fallback-filter: { geoip: true, ipcidr: [ 240.0.0.0/4, 0.0.0.0/32 ] }
rules:
  - DOMAIN-SUFFIX,bing.com,PROXY
  - DOMAIN-SUFFIX,openai.com,PROXY
  - DOMAIN-SUFFIX,bing.cn,PROXY
  - DOMAIN-SUFFIX,googleapis.com,PROXY
  - GEOSITE,category-ads-all,REJECT
  - DOMAIN-SUFFIX,appcenter.ms,REJECT
  - DOMAIN-SUFFIX,app-measurement.com,REJECT
  - DOMAIN-SUFFIX,firebase.io,REJECT
  - DOMAIN-SUFFIX,crashlytics.com,REJECT
  - DOMAIN-SUFFIX,google-analytics.com,REJECT
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT
  - GEOIP,LAN,DIRECT
  - MATCH,PROXY
"""

TEMPLATE_META_PROXY_ADDONS = """
proxies:
  - {proxy}
proxy-groups:
  - {proxy_group}
"""


@dataclass
class Project:
    workstation = Path("/home/tuic-server")
    tuic_executable = workstation.joinpath("tuic")
    server_config = workstation.joinpath("server_config.json")

    client_nekoray_config = workstation.joinpath("nekoray_config.json")
    client_meta_config = workstation.joinpath("meta_config.yaml")

    tuic_service = Path("/etc/systemd/system/tuic.service")

    _server_ip = ""

    def __post_init__(self):
        os.makedirs(self.workstation, exist_ok=True)

    @property
    def server_ip(self):
        return self._server_ip

    @server_ip.setter
    def server_ip(self, ip: str):
        self._server_ip = ip


@dataclass
class Certificate:
    domain: str

    @property
    def fullchain(self):
        return f"/etc/letsencrypt/live/{self.domain}/fullchain.pem"

    @property
    def privkey(self):
        return f"/etc/letsencrypt/live/{self.domain}/privkey.pem"


class CertBot:
    def __init__(self, domain: str):
        self._domain = domain

    def run(self):
        p = Path("/etc/letsencrypt/live/")
        if p.exists():
            logging.info("移除證書殘影...")
            for k in os.listdir(p):
                k_full = p.joinpath(k)
                if (
                    not p.joinpath(self._domain).exists()
                    and k.startswith(f"{self._domain}-")
                    and k_full.is_dir()
                ):
                    shutil.rmtree(k_full, ignore_errors=True)

        logging.info("正在为解析到本机的域名申请免费证书")
        logging.info("安装 certbot")
        os.system("apt install certbot -y > /dev/null 2>&1")
        logging.info("检查 80 端口占用")
        os.system("systemctl stop nginx > /dev/null 2>&1 && nginx -s stop")
        logging.info("开始申请证书")
        cmd = (
            "certbot certonly "
            "--standalone "
            "--register-unsafely-without-email "
            "--agree-tos "
            "-d {domain}"
        )
        p = subprocess.Popen(
            cmd.format(domain=self._domain).split(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            text=True,
        )
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
        """部署服务之前需要先初始化服务端配置并将其写到工作空间"""
        os.system(f"systemctl enable --now {self.name}")
        logging.info("系统服务已启动")
        logging.info("已设置服务开机自启")

    def stop(self):
        logging.info("停止系统服务")
        os.system(f"systemctl stop {self.name}")

    def status(self) -> Tuple[bool, str]:
        result = subprocess.run(
            f"systemctl is-active {self.name}".split(), capture_output=True, text=True
        )
        text = result.stdout.strip()
        response = None
        if text == "inactive":
            text = "\033[91m" + text + "\033[0m"
        elif text == "active":
            text = "\033[32m" + text + "\033[0m"
            response = True
        return response, text

    def remove(self, workstation: Path):
        logging.info("注销系统服务")
        os.system(f"systemctl disable --now {self.name} > /dev/null 2>&1")

        logging.info("关停相关进程")
        os.system("pkill tuic")

        logging.info("移除系统服务配置文件")
        os.remove(self.path)

        logging.info("移除工作空间")
        shutil.rmtree(workstation)


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
        data = json.loads(fp.read_text(encoding="utf8"))
        return cls(
            **{
                key: (data[key] if val.default == val.empty else data.get(key, val.default))
                for key, val in inspect.signature(cls).parameters.items()
            }
        )

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

    def to_json(self, sp: Path):
        sp.write_text(json.dumps(self.__dict__, indent=4, ensure_ascii=True))
        logging.info(f"保存服务端配置文件 - save_path={sp}")


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
class NekoRayConfig:
    """
    https://github.com/EAimTY/tuic/tree/dev/tuic-client
    Config template of tuic-client(v1.0.0)
    Apply on the NekoRay(v3.8)
    """

    relay: Dict[str, Any] = field(default_factory=dict)
    local: Dict[str, Any] = field(default_factory=dict)
    log_level: Literal["warn", "info", "debug", "error"] = "warn"

    @classmethod
    def from_server(cls, relay: ClientRelay, server_addr: str, server_ip: str | None = None):
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

    def to_json(self, sp: Path):
        sp.write_text(json.dumps(self.__dict__, indent=4, ensure_ascii=True))

    @property
    def showcase(self) -> str:
        return json.dumps(self.__dict__, indent=4, ensure_ascii=True)


@dataclass
class ClashMetaConfig:
    # 在 meta_config.yaml 中的配置内容
    contents: str

    @classmethod
    def from_server(cls, relay: ClientRelay, server_addr: str, server_ip: str | None = None):
        def from_string_to_yaml(s: str):
            _suffix = ", "
            fs = _suffix.join([i.strip() for i in s.split("\n") if i])
            fs = fs[: len(fs) - len(_suffix)]
            return "{ " + fs + " }"

        def remove_empty_lines(s: str):
            lines = s.split("\n")
            non_empty_lines = [line for line in lines if line.strip()]
            return "\n".join(non_empty_lines)

        name = "tunic"

        proxy = f"""
        name: "{name}"
        type: tuic
        server: {server_addr}
        port: 46676
        uuid: {relay.uuid}
        password: "{relay.password}"
        ip: {server_ip or ''}
        udp_relay_mode: {relay.udp_relay_mode}
        congestion_control: {relay.congestion_control}
        alpn: {relay.alpn}
        """

        proxy_group = f"""
        name: PROXY
        type: select
        proxies: ["{name}"]
        """

        proxy = from_string_to_yaml(proxy)
        proxy_group = from_string_to_yaml(proxy_group)

        addons = TEMPLATE_META_PROXY_ADDONS.format(proxy=proxy, proxy_group=proxy_group)
        contents = TEMPLATE_META_CONFIG + addons
        contents = remove_empty_lines(contents)

        return cls(contents=contents)

    def to_yaml(self, sp: Path):
        sp.write_text(self.contents + "\n")


# =================================== DataModel ===================================
TEMPLATE_PRINT_NEKORAY = """
\033[36m--> NekoRay 自定义核心配置\033[0m
# 名称：(custom)
# 地址：{server_addr}
# 端口：{listen_port}
# 命令：-c %config%
# 核心：tuic

{nekoray_config}
"""

TEMPLATE_PRINT_META = """
\033[36m--> Clash.Meta 配置文件输出路径\033[0m
{meta_path}
"""


def gen_clients(server_addr: str, user: User, server_config: ServerConfig, project: Project):
    """
    client: Literal["NekoRay", "v2rayN", "Meta"]

    :param server_addr:
    :param user:
    :param server_config:
    :param project:
    :return:
    """
    logging.info("正在生成客户端配置文件")

    # 生成客户端通用实例
    relay = ClientRelay.copy_from_server(server_addr, user, server_config)

    # 生成 NekoRay 客户端配置实例
    # https://matsuridayo.github.io/n-extra_core/
    nekoray = NekoRayConfig.from_server(relay, server_addr, project.server_ip)
    nekoray.to_json(project.client_nekoray_config)
    print(
        TEMPLATE_PRINT_NEKORAY.format(
            server_addr=server_addr, listen_port=LISTEN_PORT, nekoray_config=nekoray.showcase
        )
    )

    # 生成 Clash.Meta 客户端配置实例
    # https://wiki.metacubex.one/config/proxies/tuic/
    meta = ClashMetaConfig.from_server(relay, server_addr, project.server_ip)
    meta.to_yaml(project.client_meta_config)
    print(TEMPLATE_PRINT_META.format(meta_path=project.client_meta_config))


def _validate_domain(domain: str | None) -> Union[NoReturn, Tuple[str, str]]:
    """

    :param domain:
    :return: Tuple[domain, server_ip]
    """
    if not domain:
        domain = input("> 解析到本机的域名：")

    try:
        server_ip = socket.getaddrinfo(domain, None)[-1][4][0]
    except socket.gaierror:
        logging.error(f"域名不可达或拼写错误的域名 - {domain=}")
    else:
        my_ip = request.urlopen("http://ifconfig.me/ip").read().decode("utf8")
        if my_ip != server_ip:
            logging.error(f"你的主机外网IP与域名解析到的IP不一致 - {my_ip=} {domain=} {server_ip=}")
        else:
            return domain, server_ip

    # 域名解析错误，应当阻止用户执行安装脚本
    sys.exit()


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
        (domain, server_ip) = _validate_domain(params.domain)
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
        user = User.gen()

        # 初始化系统服务配置
        project.server_ip = server_ip
        template = TEMPLATE_SERVICE.format(
            exec_start=f"{project.tuic_executable} -c {project.server_config}",
            working_directory=f"{project.workstation}",
        )
        tuic = TuicService.build_from_template(path=project.tuic_service, template=template)

        logging.info(f"正在下载 tuic-server")
        tuic.download_tuic_server(project.tuic_executable)

        logging.info("正在生成默认的服务端配置")
        server_config = ServerConfig.from_automation(user, cert.fullchain, cert.privkey)
        server_config.to_json(project.server_config)

        logging.info("正在部署系统服务")
        tuic.start()

        logging.info("正在检查服务状态")
        (response, text) = tuic.status()

        # 在控制台输出客户端配置
        if response is True:
            gen_clients(domain, user, server_config, project)
        else:
            logging.info(f"{text}")

    @staticmethod
    def remove(params: argparse.Namespace):
        (domain, _) = _validate_domain(params.domain)
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
