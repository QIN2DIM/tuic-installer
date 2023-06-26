# Tunic

一键部署 tuic-server

## 先决条件

你需要为你的服务器解析一个域名A纪录。

## Get started

### 一键部署

拉取仓库脚本，在交互式引导下完成部署：

```shell
curl -O url | python3 install 
```

也可以直接指定域名参数一气呵成：

```shell
curl -O url | python3 install -d DOMAIN
```

###　客户端配置

tuic-server service 部署完成后，脚本会在控制台打印相应的客户端配置模版。

- [ ] [NekoRay](https://github.com/MatsuriDayo/nekoray)
- [ ] [v2rayN](https://github.com/2dust/v2rayN)

### 移除负载

必须指定运行 tuic-server 用到的域名才能安全卸载证书。这个指令会移除与 tuic-server 有关的一切依赖，包括 Python 脚本本身。

```shell
curl -O url | python3 remove -d DOMAIN
```

