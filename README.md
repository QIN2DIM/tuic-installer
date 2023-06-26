# Tunic

一键部署 [tuic-server](https://github.com/EAimTY/tuic)

## 先决条件

1. 你需要为你的服务器解析一个域名A纪录。
2. 2023了，你的服务器上起码得有 **Python3** 了。

## Get started

### 一键部署

拉取仓库脚本，在交互式引导下完成部署：

```shell
python3 <(curl -fsSL https://ros.services/tunic.py) install
```

也可以直接指定域名参数一气呵成：

```shell
python3 <(curl -fsSL https://ros.services/tunic.py) remove
```

### 客户端配置

`tuic-server` Service 部署完成后，脚本会在控制台打印相应的客户端配置模版。

- [x] [NekoRay](https://github.com/MatsuriDayo/nekoray)
- [ ] [v2rayN](https://github.com/2dust/v2rayN)

### 移除负载

这个指令会移除与 `tuic-server` 有关的一切依赖。需要注意的是，你必须指明与 `tuic-server` 绑定的域名才能安全卸载证书。

```shell
curl -O url | python3 remove -d DOMAIN
```

