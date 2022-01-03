FROM golang:1.16-buster as build

WORKDIR /go/src/github.com/borancar/talos-pxe

COPY go.mod .
COPY go.sum .
COPY main.go .
COPY dhcp.go .
COPY tftp.go .
COPY pxe.go .
COPY tftp.go .
COPY dns.go .
COPY server.go .
COPY vendor vendor

RUN go install
RUN echo 'alias ll="ls -lah --color"' >> /root/.bashrc

FROM build as unittest

COPY *_test.go .
COPY Makefile .
ENTRYPOINT ["make", "unittest-local"]

FROM debian:buster-slim as talos-pxe

COPY --from=build /go/bin/talos-pxe /go/bin/talos-pxe
COPY undionly.kpxe /srv/tftp/
COPY ipxe.efi /srv/tftp/

COPY assets /srv/assets
COPY profiles /srv/profiles
COPY groups /srv/groups

ENTRYPOINT ["/go/bin/talos-pxe"]
CMD ["--root", "/srv"]
