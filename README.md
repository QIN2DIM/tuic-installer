# Tunic

一键部署 [tuic-server](https://github.com/EAimTY/tuic)！

## Prerequisites

- Python3.8+
- 在管理员权限下运行
- 提前为你的服务器解析一个域名 A 纪录

## Get started

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

3. **Next step**

   查看 [项目 WiKi](https://github.com/QIN2DIM/tuic-installer/wiki/Usage) 以获取完整的技术文档🐧
