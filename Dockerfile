# Need at least glibc, libelf, libz installed to run xdp-loader, bpftool, and other binaries

# Use a slightly older version of fedora so it's linked to an older version of glibc (v2.29)
FROM fedora:32 AS builder
RUN dnf -y update && \
    dnf install -y clang llvm gcc elfutils-libelf-devel glibc-devel.i686 m4 libpcap-devel make bison flex && \
    dnf install -y findutils vim git
COPY ./ /tmp/xdp
RUN make -C /tmp/xdp/src

FROM golang:alpine as gobuilder
COPY ./src/sockmap_daemon.go $GOPATH/src
RUN cd $GOPATH/src && go mod init sockmap && ls -al /go/src
RUN cd $GOPATH/src && go get github.com/moby/sys/mountinfo
RUN cd $GOPATH/src && go build -o /sockmap_daemon

FROM frolvlad/alpine-glibc:alpine-3.14_glibc-2.33
RUN apk add libelf
RUN mkdir -p /root/bin
COPY --from=builder /tmp/xdp/src/.output/bpftool/bpftool /root/bin/
COPY --from=builder /tmp/xdp/src/.output/sockmap_redir.o /root/bin/
COPY --from=builder /tmp/xdp/src/.output/sockops.o /root/bin/
COPY --from=gobuilder /sockmap_daemon /root/bin/sockmap_daemon
