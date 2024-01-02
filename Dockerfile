# Important Notes:
#
# Two local dependencies should be ready before build container image with the Dockerfile.
# - MLNX_OFED: Please download it from the official website
#   `https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/`
#   to the local fileserver indicated by the ARG `MLNX_OFED`.
#   We cannot download it in the Dockerfile automatically for the authentication
#   restriction of the website.
# - RPM_PKGCONFIG: The `pkg-config` tool of v0.29.2 is required to build DPVS.
#   However, the default installation version on centos7 is v0.27.1. You need to
#   download it or build the v0.29.2 RPM from source and put it to the the local
#   fileserver indicated by the ARG `RPM_PKGCONFIG`. Alternatively, building a
#   binary `pkg-config` and installing it in the local binary path is also ok.
#
#   No kernel dependencies of dpdk/dpvs or network driver are built and installed.
#   You should ensure the host has installed the drivers before running a dpvs
#   container on it.
#

ARG BASE_IMAGE=centos:centos7.9.2009

###### `builder` stage builds the docker image for DPVS devel environments ######
FROM $BASE_IMAGE as builder

# replace it with the address of your own file server
ARG FILE_SERVER=127.0.0.1

LABEL maintainer="IQiYi/QLB team"
LABEL email="iig_cloud_qlb@qiyi.com"
LABEL project="https://github.com/iqiyi/dpvs"
LABEL image_maker="docker build --target builder -t github.com/iqiyi/dpvs-builder:{version} ."

# download the tarball from https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/
# FIXME: remove thefile server dependency
ARG MLNX_OFED=http://$FILE_SERVER/deploy/MLNX_OFED/MLNX_OFED_LINUX-5.6-2.0.9.0-rhel7.9-x86_64.tgz

# the pkgconfig default installed version is 0.27.1 on centos7, update it to 0.29.2
# the 0.29.2 rpm is built from source based on the rpm spec file of 0.27.1.
# FIXME: remove the file server dependency
ARG RPM_PKGCONFIG=http://$FILE_SERVER/deploy/rpms/centos7/pkgconfig-0.29.2-1.el7.x86_64.rpm

# golang install files
ARG GO_PACKAGE=https://go.dev/dl/go1.20.4.linux-amd64.tar.gz

# go-swagger binary
ARG GO_SWAGGER_BIN=https://github.com/go-swagger/go-swagger/releases/download/v0.30.4/swagger_darwin_amd64

ENV PKG_CONFIG_PATH=/dpvs/dpdk/dpdklib/lib64/pkgconfig
ENV PATH=$PATH:/usr/local/go/bin

COPY . /dpvs/
WORKDIR /dpvs

RUN set -x \
        && yum install -y epel-release \
        && yum install -y tcl tk iproute wget vim patch meson python36 emacs-filesystem \
                gcc make lsof libnl3 ethtool libpcap pciutils numactl-libs numactl-devel \
                openssl-devel automake popt-devel ninja-build meson libnl3-devel cgdb git \
        && mkdir deps \
        && rpm -Uvh $RPM_PKGCONFIG \
        && wget $GO_PACKAGE -P deps \
        && tar -C /usr/local -xzf deps/go*.gz \
        && curl -L -o /usr/local/bin/swagger $GO_SWAGGER_BIN \
        && chmod 544 /usr/local/bin/swagger \
        && wget $MLNX_OFED -P deps \
        && tar xf deps/$(basename $MLNX_OFED) -C deps \
        && pushd deps/$(basename $MLNX_OFED | sed 's/.tgz//') \
        && ./mlnxofedinstall --user-space-only --upstream-libs \
                --dpdk --without-fw-update --force \
        && popd \
        && sed -i 's/Denable_kmods=true/Denable_kmods=false/' scripts/dpdk-build.sh \
        && ./scripts/dpdk-build.sh \
        && sed -i 's/CONFIG_DPVS_AGENT=n/CONFIG_DPVS_AGENT=y/' config.mk \
        && make -j && make install \
        && rm -rf deps && yum clean all

RUN set -x \
        && mkdir libraries \
        && ldd bin/dpvs | grep "=> /" | awk '{print $3}' | xargs -I '{}' cp '{}' libraries \
        && ldd bin/ipvsadm | grep "=> /" | awk '{print $3}' | xargs -I '{}' cp '{}' libraries \
        && ldd bin/dpip | grep "=> /" | awk '{print $3}' | xargs -I '{}' cp '{}' libraries \
        && ldd bin/keepalived | grep "=> /" | awk '{print $3}' | xargs -I '{}' cp '{}' libraries

ENTRYPOINT ["/bin/bash"]


###### `runner` stage builds the docker image for DPVS product environments ######
#
# docker run --name dpvs \
#       -d --privileged --network host \
#       -v /dev:/dev \
#       -v /sys:/sys \
#       -v /lib/modules:/lib/modules \
#       -v {dpvs-directory}:/dpvs \
#       github.com/iqiyi/dpvs:{version} \
#       -c /dpvs/dpvs.conf -p /dpvs/dpvs.pid -x /dpvs/dpvs.ipc \
#       -- -a {nic-pci-bus-id}
#
# docker run --name ipvsadm \
#       --rm --network none \
#       -v {dpvs-directory}:/dpvs \
#       -e DPVS_IPC_FILE=/dpvs/dpvs.ipc \
#       --entrypoint=/usr/bin/ipvsadm \
#       github.com/iqiyi/dpvs:{version} \
#       ...
#
# docker run --name dpip \
#       --rm --network none \
#       -v {dpvs-directory}:/dpvs \
#       -e DPVS_IPC_FILE=/dpvs/dpvs.ipc \
#       --entrypoint=/usr/bin/dpip \
#       github.com/iqiyi/dpvs:{version} \
#       ...
#
# docker run --name keepalived \
#       -d --privileged --network host  \
#       --cap-add=NET_ADMIN --cap-add=NET_BROADCAST --cap-add=NET_RAW \
#       -v {dpvs-directory}:/dpvs \
#       -e DPVS_IPC_FILE=/dpvs/dpvs.ipc \
#       --entrypoint=/usr/bin/keepalived github.com/iqiyi/dpvs:{version} \
#       -D -n -f /dpvs/keepalived.conf \
#       --log-console --log-facility=6 \
#       --pid=/dpvs/keepalived.pid \
#       --vrrp_pid=/dpvs/vrrp.pid \
#       --checkers_pid=/dpvs/checkers.pid
#
# docker run --name dpvs-agent \
#       -d --network host \
#       -v {dpvs-directory}:/dpvs \
#       --entrypoint=/usr/bin/dpvs-agent \
#       github.com/iqiyi/dpvs:{version} \
#       --log-dir=/dpvs/logs/dpvs-agent \
#       --ipc-sockopt-path=/dpvs/dpvs.ipc\
#       --host=0.0.0.0 --port=6601
#
# docker run --name healthcheck \
#       -d --network host \
#       -v {dpvs-directory}:/dpvs \
#       --entrypoint=/usr/bin/healthcheck \
#       github.com/iqiyi/dpvs:{version} \
#       -log_dir=/dpvs/logs/healthcheck \
#       -lb_iface_addr=localhost:6601
#
FROM $BASE_IMAGE as runner

LABEL maintainer="IQiYi/QLB team"
LABEL email="iig_cloud_qlb@qiyi.com"
LABEL project="https://github.com/iqiyi/dpvs"
LABEL image_maker="docker build --target runner -t github.com/iqiyi/dpvs:{version} ."

RUN set -x \
        && yum install -y iproute wget ncat nmap tcpdump socat \
        && yum clean all

COPY --from=builder /dpvs/bin/ /usr/bin
COPY --from=builder /dpvs/libraries /usr/lib64

# Other available entrypoint are:
#  * /usr/bin/keepalived
#  * /usr/bin/dpvs-agent
#  * /usr/bin/healthcheck
#  * /usr/bin/ipvsadm
#  * /usr/bin/dpip
#  * /bin/bash
# use `docker run --entrypoint ...` to override the default entrypoint.

ENTRYPOINT ["/usr/bin/dpvs"]
