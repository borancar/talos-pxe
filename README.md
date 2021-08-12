# talos-pxe

Talos PXE is a project aimed at boostrapping an initial Talos cluster from a single bootable USB stick. This stick plugs into an avaiable computer and will provide a selection menu for any PXE bootable machine connected to the same network. The software is able to adapt to an existing DHCP server via proxyDHCP or provide a DHCP server of its own.

![iPXE Talos menu screenshot](screenshot.png)


## Requirements

- Docker
- Golang version 1.16.7
- LinuxKit

## Building

You need to download the Talos kernel and initramfs before proceeding. These should be placed in `assets`:

```
assets/initramfs-amd64.xz
assets/vmlinuz-amd64
```

Generate the configuration via:

```
talosctl gen config -o assets talos-k8s-metal-tutorial https://controlplane.local:8443
sed 's/type: controlplane/type: init/' assets/controlplane.yaml > assets/init.yaml
```

First step is building the pxe network container via:

```
docker build -t pxe .
```

then that container can be converted into a bootable VM via LinuxKit:

```
linuxkit build -docker -format iso-bios linux.yml
```
