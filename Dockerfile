# Need at least glibc, libelf, libz installed to run xdp-loader, bpftool, and other binaries

# Use a slightly older version of fedora so it's linked to an older version of glibc (v2.29)
FROM fedora:32 AS builder
RUN dnf -y update && \
    dnf install -y clang llvm gcc elfutils-libelf-devel glibc-devel.i686 m4 libpcap-devel make bison flex && \
    dnf install -y findutils vim git
COPY ./ /tmp/xdp
RUN make -C /tmp/xdp/src

FROM debian:latest as bpftool
RUN apt-get update -y
RUN apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev \
	clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev \
	bison flex libbpf-dev iproute2 jq wget apt binutils-dev
RUN git clone --depth 1 -b master git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git /tmp/linux && \
cd /tmp/linux/tools/bpf/bpftool/ &&\
sed -i '/CFLAGS += -O2/a CFLAGS += -static' Makefile && \
sed -i 's/LIBS = -lelf $(LIBBPF)/LIBS = -lelf -lz $(LIBBPF)/g' Makefile && \
printf 'feature-libbfd=0\nfeature-libelf=1\nfeature-bpf=1\nfeature-libelf-mmap=1' >> FEATURES_DUMP.bpftool && \
FEATURES_DUMP=`pwd`/FEATURES_DUMP.bpftool make -j `getconf _NPROCESSORS_ONLN` && \
strip bpftool && \
ldd bpftool 2>&1 | grep -q -e "Not a valid dynamic program" \
	-e "not a dynamic executable" || \
	( echo "Error: bpftool is not statically linked"; false )

FROM golang:alpine as gobuilder
COPY ./src/sockmap_daemon.go $GOPATH/src
RUN cd $GOPATH/src && go mod init sockmap && ls -al /go/src
RUN cd $GOPATH/src && go get github.com/moby/sys/mountinfo
RUN cd $GOPATH/src && go build -o /sockmap_daemon

FROM frolvlad/alpine-glibc:alpine-3.14_glibc-2.33
RUN apk add libelf
RUN mkdir -p /root/bin
COPY --from=bpftool /tmp/linux/tools/bpf/bpftool/bpftool /root/bin/
COPY --from=builder /tmp/xdp/src/.output/sockmap_redir.o /root/bin/
COPY --from=builder /tmp/xdp/src/.output/sockops.o /root/bin/
COPY --from=gobuilder /sockmap_daemon /root/bin/sockmap_daemon
