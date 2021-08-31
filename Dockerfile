FROM golang:1.16-buster as build

WORKDIR /go/src/github.com/borancar/talos-pxe

COPY go.mod .
COPY go.sum .
COPY main.go .
COPY dhcp.go .
COPY tftp.go .
COPY pxe.go .
COPY tftp.go .
COPY logging.go .
COPY dns.go .
COPY vendor vendor

RUN go install

FROM debian:buster-slim

COPY --from=build /go/bin/talos-pxe /go/bin/talos-pxe
COPY undionly.kpxe /srv/tftp/
COPY ipxe.efi /srv/tftp/

COPY assets /srv/assets
COPY profiles /srv/profiles
COPY groups /srv/groups

ENTRYPOINT ["/go/bin/talos-pxe"]
CMD ["--root", "/srv"]
