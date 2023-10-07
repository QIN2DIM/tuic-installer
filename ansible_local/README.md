# Ansible Install

## Get started

### Local deploy

1. Modify the `kvm.hosts.localhost.tunic_domain` field of `inventory.yaml` to the domain name of IPv4 resolved to the localhost. 

2. Run the following command to install tuic-server in the localhost
```bash
# /path/to/tuic-installer/ansible
ansible-playbook local_deploy.yaml
```

### Check configuration of client outbound

| Implement                                                    | Command                                      |
| ------------------------------------------------------------ | -------------------------------------------- |
| [NekoRay](https://matsuridayo.github.io/n-extra_core/)       | `more /home/tuic-server/nekoray_config.json` |
| [Clash.Meta](https://wiki.metacubex.one/config/proxies/tuic/) | `more /home/tuic-server/meta_config.yaml`    |
| [sing-box](https://sing-box.sagernet.org/configuration/outbound/tuic/) | `more /home/tuic-server/singbox_config.json` |

### Check runtime-config of tuic-server

```
more /home/tuic-server/server_config.json
```

