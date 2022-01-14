# talos-pxe

Talos PXE is a project aimed at boostrapping an initial Talos cluster from a single bootable USB stick. This stick plugs into an avaiable computer and will provide a selection menu for any PXE bootable machine connected to the same network. The software is able to adapt to an existing DHCP server via proxyDHCP or provide a DHCP server of its own.

![iPXE Talos menu screenshot](screenshot.png)

## Requirements

- Docker
- Golang version 1.16.7
- LinuxKit

## Building

You need to download the Talos kernel and initramfs before proceeding. Files can be found on [talos release page](https://github.com/talos-systems/talos/releases) These should be placed in `assets`:

```
assets/initramfs-amd64.xz
assets/vmlinuz-amd64
```

Generate the configuration via:

```
talosctl gen config -o assets talos-k8s-metal-tutorial https://controlplane.talos:8443
sed 's/type: controlplane/type: init/' assets/controlplane.yaml > assets/init.yaml
```

First step is building the pxe network container via:

```
docker build -t talos-pxe --target talos-pxe .
```

then that container can be converted into a bootable VM via LinuxKit:

```
linuxkit build -docker -format iso-bios linux.yml

(if you get a VFS error booting this image, you may need to try other formats like `raw-bios` or `raw-efi`)
```

## Unittests

Unittests are run in a docker container, that is build before the tests, so they can be run on Linux or Mac. (I have not tried 
Windows). Coverage files can be found after run in out/coverage.html 

```bash
make unittest
```

One test can be run with following make target:

```bash
make unittest-one TEST_PATTERN=<test name>
```

## Local verification setup

Disclaimer: This setup will probably not work for you, but it can remind me in a few months how to set this thing up.
Used virtualization `libvirt + KVM`

### Setup for verifying DHCP no proxy mode

1. Do steps from build section, about assets and talos configs 
2. Set required capabilities on the talos-pxe binary
    ```bash
    sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ./talos-pxe
    ```
3. Stop DHCP servis 


