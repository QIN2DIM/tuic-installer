# Ansible Install

## Get started

### Local deploy

1. Modify the `kvm.hosts.localhost.tunic_domain` field of `inventory.yaml` to the domain name of IPv4 resolved to the localhost. 

2. Run the following command to install tuic-server in the localhost
```bash
# /path/to/tuic-installer/ansible
ansible-playbook local_deploy.yaml
```
