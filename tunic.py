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
import random
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

# https://adguard-dns.io/kb/zh-CN/general/dns-providers
# https://github.com/MetaCubeX/Clash.Meta/blob/53f9e1ee7104473da2b4ff5da29965563084482d/config/config.go#L891
TEMPLATE_META_CONFIG = """
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - "https://dns.google/dns-query#PROXY"
    - "https://security.cloudflare-dns.com/dns-query#PROXY"
    - "quic://dns.adguard-dns.com"
  proxy-server-nameserver:
    - system
  nameserver-policy:
    "geosite:cn":
      - system
rules:
  - GEOSITE,category-scholar-!cn,PROXY
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,youtube,PROXY
  - GEOSITE,google,PROXY
  - GEOSITE,cn,DIRECT
  - GEOSITE,private,DIRECT
  - GEOSITE,tracker,DIRECT
  - GEOSITE,steam@cn,DIRECT
  - GEOSITE,category-games@cn,DIRECT
  - GEOSITE,geolocation-!cn,PROXY
  - GEOIP,private,DIRECT,no-resolve
  - GEOIP,telegram,PROXY
  - GEOIP,CN,DIRECT
  - DST-PORT,80/8080/443/8443,PROXY
  - MATCH,DIRECT
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

    # 设置别名
    path_bash_aliases = Path("/root/.bash_aliases")
    _remote_command = "python3 <(curl -fsSL https://ros.services/tunic.py)"
    _alias = "tunic"

    _server_ip = ""
    _server_port = -1

    def __post_init__(self):
        os.makedirs(self.workstation, exist_ok=True)

    @staticmethod
    def is_port_in_used(_port: int, proto: Literal["tcp", "udp"]) -> bool | None:
        """Check socket UDP/data_gram or TCP/data_stream"""
        proto2type = {"tcp": socket.SOCK_STREAM, "udp": socket.SOCK_DGRAM}
        socket_type = proto2type[proto]
        with suppress(socket.error), socket.socket(socket.AF_INET, socket_type) as s:
            s.bind(("127.0.0.1", _port))
            return False
        return True

    @property
    def server_ip(self):
        return self._server_ip

    @server_ip.setter
    def server_ip(self, ip: str):
        self._server_ip = ip

    @property
    def server_port(self):
        # 初始化监听端口
        if self._server_port < 0:
            rand_ports = list(range(41670, 46990))
            random.shuffle(rand_ports)
            for p in rand_ports:
                if not self.is_port_in_used(p, proto="udp"):
                    self._server_port = p
                    logging.info(f"正在初始化监听端口 - port={p}")
                    break

        # 返回已绑定的空闲端口
        return self._server_port

    @property
    def alias(self):
        return f"alias {self._alias}='{self._remote_command}'"

    def set_alias(self):
        with open(self.path_bash_aliases, "a", encoding="utf8") as file:
            file.write(f"\n{self.alias}\n")
        logging.info(f"✅ 你可以在重启会话后通过别名唤起脚本 - alias={self._alias}")

    def remove_alias(self):
        text = self.path_bash_aliases.read_text(encoding="utf8")
        for ck in [f"\n{self.alias}\n", f"\n{self.alias}", f"{self.alias}\n", self.alias]:
            text = text.replace(ck, "")
        self.path_bash_aliases.write_text(text, encoding="utf8")


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

        logging.info("正在更新包索引")
        os.system("apt update -y > /dev/null 2>&1 ")

        logging.info("安装 certbot")
        os.system("apt install certbot -y > /dev/null 2>&1")

        logging.info("检查 80 端口占用")
        if Project.is_port_in_used(80, proto="tcp"):
            # 执行温和清理
            os.system("systemctl stop nginx > /dev/null 2>&1 && nginx -s stop > /dev/null 2>&1")
            os.system("kill $(lsof -t -i:80)  > /dev/null 2>&1")

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


# =================================== Runtime Settings ===================================


def from_dict_to_cls(cls, data):
    return cls(
        **{
            key: (data[key] if val.default == val.empty else data.get(key, val.default))
            for key, val in inspect.signature(cls).parameters.items()
        }
    )


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
    zero_rtt_handshake: bool = True

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
        return from_dict_to_cls(cls, data)

    @classmethod
    def from_automation(
        cls, users: List[User] | User, path_fullchain: str, path_privkey: str, server_port: int
    ):
        if not isinstance(users, list):
            users = [users]
        users = {user.username: user.password for user in users}
        server = f"[::]:{server_port}"
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
    Because this script implements the steps of automatic certificate application, this parameter will never be used.
    """
    certificates: List[str] | None = field(default_factory=list)

    """
    // Optional. Set the UDP packet relay mode
    // Can be:
    // - "native": native UDP characteristics
    // - "quic": lossless UDP relay using QUIC streams, additional overhead is introduced
    // Default: "native"
    """
    udp_relay_mode: Literal["native", "quic"] = "quic"

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
    // Optional. Enable 0-RTT QUIC connection handshake on the client side
    // This is not impacting much on the performance, as the protocol is fully multiplexed
    // WARNING: Disabling this is highly recommended, as it is vulnerable to replay attacks. See https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones
    // Default: false
    """
    zero_rtt_handshake: bool = True

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
        self.certificates = None

    @classmethod
    def copy_from_server(cls, domain: str, user: User, sc: ServerConfig, server_port: int):
        server = f"{domain}:{server_port}"
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
    def from_server(
        cls, relay: ClientRelay, server_addr: str, server_port: int, server_ip: str | None = None
    ):
        local = ClientLocal(server="127.0.0.1:%socks_port%")

        relay.server = f"{server_addr}:{server_port}"

        if server_ip is not None:
            relay.ip = server_ip

        relay, local = relay.__dict__, local.__dict__

        local = {k: local[k] for k in local if local[k] is not None}
        relay = {k: relay[k] for k in relay if relay[k] is not None}

        return cls(relay=relay, local=local)

    @classmethod
    def from_json(cls, sp: Path):
        data = json.loads(sp.read_text(encoding="utf8"))
        return from_dict_to_cls(cls, data)

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
    def from_server(
        cls, relay: ClientRelay, server_addr: str, server_port: int, server_ip: str | None = None
    ):
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

        # https://wiki.metacubex.one/config/proxies/tuic/
        proxy = f"""
        name: "{name}"
        type: tuic
        server: {server_addr}
        port: {server_port}
        uuid: {relay.uuid}
        password: "{relay.password}"
        ip: {server_ip or ''}
        udp-relay-mode: {relay.udp_relay_mode}
        congestion-controller: {relay.congestion_control}
        alpn: {relay.alpn}
        reduce-rtt: {relay.zero_rtt_handshake}
        max-udp-relay-packet-size: 1464
        """

        # https://wiki.metacubex.one/config/proxy-groups/select/
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
    server_ip, server_port = project.server_ip, project.server_port
    relay = ClientRelay.copy_from_server(server_addr, user, server_config, server_port)

    # 生成 NekoRay 客户端配置实例
    # https://matsuridayo.github.io/n-extra_core/
    nekoray = NekoRayConfig.from_server(relay, server_addr, server_port, server_ip)
    nekoray.to_json(project.client_nekoray_config)
    print(
        TEMPLATE_PRINT_NEKORAY.format(
            server_addr=server_addr, listen_port=server_port, nekoray_config=nekoray.showcase
        )
    )

    # 生成 Clash.Meta 客户端配置实例
    # https://wiki.metacubex.one/config/proxies/tuic/
    meta = ClashMetaConfig.from_server(relay, server_addr, server_port, server_ip)
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
            logging.info(f"证书文件已存在 - path={Path(cert.fullchain).parent}")

        # 初始化 workstation
        project = Project()
        # 设置脚本别名
        project.set_alias()

        user = User.gen()
        server_port = project.server_port

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
        server_config = ServerConfig.from_automation(
            user, cert.fullchain, cert.privkey, server_port
        )
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

        # 移除脚本别名
        project.remove_alias()

        # 移除可能残留的证书文件
        CertBot(domain).remove()

        # 关停进程，注销系统服务，移除工作空间
        TuicService.build_from_template(project.tuic_service).remove(project.workstation)

    @staticmethod
    def check(params: argparse.Namespace):
        def print_nekoray():
            if not project.client_nekoray_config.exists():
                logging.error(f"❌ 客户端配置文件不存在 - path={project.client_nekoray_config}")
            else:
                nekoray = NekoRayConfig.from_json(project.client_nekoray_config)
                server_addr, server_port = nekoray.relay.get("server", "").split(":")
                print(
                    TEMPLATE_PRINT_NEKORAY.format(
                        server_addr=server_addr,
                        listen_port=server_port,
                        nekoray_config=nekoray.showcase,
                    )
                )

        def print_clash_meta():
            if not project.client_meta_config.exists():
                logging.error(f"❌ 客户端配置文件不存在 - path={project.client_meta_config}")
            else:
                print(TEMPLATE_PRINT_META.format(meta_path=project.client_meta_config))
                print("\033[36m--> Clash.Meta 配置信息\033[0m")
                print(project.client_meta_config.read_text())

        project = Project()

        show_all = not any([params.clash, params.nekoray, params.v2ray])
        if show_all:
            print_nekoray()
            print_clash_meta()
        elif params.nekoray:
            print_nekoray()
        elif params.clash:
            print_clash_meta()
        elif params.v2ray:
            logging.warning("Unimplemented feature")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TUIC Scaffold (Python3.8+)")
    subparsers = parser.add_subparsers(dest="command")

    install_parser = subparsers.add_parser("install", help="Automatically install and run")
    install_parser.add_argument("-d", "--domain", type=str, help="传参指定域名，否则需要在运行脚本后以交互的形式输入")

    remove_parser = subparsers.add_parser("remove", help="Uninstall services and associated caches")
    remove_parser.add_argument("-d", "--domain", type=str, help="传参指定域名，否则需要在运行脚本后以交互的形式输入")

    check_parser = subparsers.add_parser("check", help="Print client configuration")
    check_parser.add_argument("--nekoray", action="store_true", help="show NekoRay config")
    check_parser.add_argument("--clash", action="store_true", help="show Clash.Meta config")
    check_parser.add_argument("--v2ray", action="store_true", help="show v2rayN config")

    args = parser.parse_args()
    command = args.command

    with suppress(KeyboardInterrupt):
        if command == "install":
            Scaffold.install(params=args)
        elif command == "remove":
            Scaffold.remove(params=args)
        elif command == "check":
            Scaffold.check(params=args)
        else:
            parser.print_help()
