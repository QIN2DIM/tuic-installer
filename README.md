# Tunic

托尼老师的下饭时刻！一键部署 [tuic-server](https://github.com/EAimTY/tuic)

## Prerequisites

1. 提前为你的服务器解析一个域名 A 纪录。
2. 三二零二了，你的服务器该有 **Python3** 了。
3. `sudo -i` 切换至 root user 上下文。

## Get started

### 一键部署

拉取仓库脚本，在交互式引导下完成部署：

```shell
python3 <(curl -fsSL https://ros.services/tunic.py) install
```

也可以直接指定域名参数一气呵成：

```shell
python3 <(curl -fsSL https://ros.services/tunic.py) install -d YOUR_DOMAIN
```

`tuic-server` Service 部署完成后，脚本会在控制台打印相应的客户端配置模版。

### 移除负载

这个指令会移除与 `tuic-server` 有关的一切依赖。需要注意的是，你必须指明与 `tuic-server` 绑定的域名才能安全卸载证书。

```shell
python3 <(curl -fsSL https://ros.services/tunic.py) remove
```

## Advanced

> Q：如何加速网页的刷新速度

> Q：`udp_relay_mode` ，选择 quic 还是 native？

> Q：`congestion_control` ，流控算法 cubic，new_reno 以及 bbr 的区别是什么？如何选择？

> Q：什么是重放攻击？`zero_rtt_handshake` 开启还是关闭？为什么不推荐开启？

>  Q：`send_window` 和 `receive_window` 是什么意思？它们如何影响 tuic 的流控行为？默认配置能否满足你的需求？如何计算合理取值？

>  Q：**tuic** vs **hysteria (v1 / v2)** ！它们的区别是什么，普通开发者应该如何选择？

> Q：**tuic** 有 Rust (Origin) 和 Golang ([clash.meta](https://wiki.metacubex.one/config/proxies/tuic/)) 兩種實現，它们的区别是什么? 如何選擇

## RoadMap

1. 添加更多的客户端配置模版（Priority: A+）

   - [x] NekoRay

   - [x] clash.meta

   - [ ] v2rayN

   - [ ] kubernetes ingress proxy-chain

2. 完善脚手架指令（Priority: A-）

   - [x] 增

   - [x] 删

   - [ ] 改

   - [ ] 查

   - [ ] 通过命令行修改运行配置

3. Advanced content, migrate it to blog. （Priority: B）
