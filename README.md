# Tunic <a href = "https://t.me/+-Sux5u3PUpJiY2Ix"><img src="https://img.shields.io/static/v1?style=social&logo=telegram&label=chat&message=studio" ></a>

Tunic 用于快速部署 [tuic-server](https://github.com/EAimTY/tuic) 并输出客户端最佳实践配置。只需 15s 即可完成全自动部署，开箱即用！

## Prerequisites

- Python3.8+
- 在管理员权限下运行
- 提前为你的服务器解析一个域名 A 纪录

## Get started

> 首次安装完毕后，你可以通过别名指令 `tunic` 调度脚本。

1. **One-Click deployment**

   在交互式引导下完成部署。脚本会在任务结束后打印代理客户端配置。
   ```shell
   python3 <(curl -fsSL https://ros.services/tunic.py) install
   ```

   也可以直接指定域名参数「一步到胃」：

   ```shell
   python3 <(curl -fsSL https://ros.services/tunic.py) install -d YOUR_DOMAIN
   ```

2. **Remove loads**

   这个指令会移除与 `tuic-server` 有关的一切依赖。需要注意的是，你必须指明与 `tuic-server` 绑定的域名才能安全卸载证书。

   ```shell
   python3 <(curl -fsSL https://ros.services/tunic.py) remove
   ```

3. **Common**

   默认情况下会打印所有客户端配置，但你可以通过可选的过滤指令仅输出 `NekoRay` / `clash-meta` / `sing-box` 的客户端出站配置：

   | Client                                                       | Command                                                      |
   | ------------------------------------------------------------ | ------------------------------------------------------------ |
   | [NekoRay](https://matsuridayo.github.io/n-extra_core/)       | `python3 <(curl -fsSL https://ros.services/tunic.py) install --neko` |
   | [Clash.Meta](https://wiki.metacubex.one/config/proxies/tuic/) | `python3 <(curl -fsSL https://ros.services/tunic.py) install --clash` |
   | [sing-box](https://sing-box.sagernet.org/configuration/outbound/tuic/) | `python3 <(curl -fsSL https://ros.services/tunic.py) install --singbox` |

   你可以配合 `-d` 指定域名实现「一键输出」的效果，如：

   ```bash
   python3 <(curl -fsSL https://ros.services/tunic.py) install --singbox -d YOUR_DOMAIN
   ```

   首次安装后，你还可以使用别名缩写去更新（覆盖）双端配置，如：

   ```bash
   tunic install --singbox -d YOUR_DOMAIN

4. **Next steps**

   查看 [项目 WiKi](https://github.com/QIN2DIM/tuic-installer/wiki/Usage) 以获取完整的技术文档🐧
