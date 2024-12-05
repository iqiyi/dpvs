#!/bin/env bash
############################################################################
# usage: $0 [-v dpdk-version] [-d] [-w work-directory] [-p patch-directory]

build_options="-Denable_kmods=true"
debug_options="-Dbuildtype=debug -Dc_args=-DRTE_MALLOC_DEBUG"

dpdkver=20.11.10                            # default dpdk version (use stable version)
workdir=$(pwd)/dpdk/
patchdir=""

function help()
{
    local default_patchdir=$(realpath ./patch/dpdk-stable-${dpdkver})
    echo -e "\033[31musage: $0 [-d] [-w work-directory] [-p patch-directory]\033[0m"
    echo -e "\033[31mOPTIONS:\033[0m"
    echo -e "\033[31m    -v    specify the dpdk version, default ${dpdkver}\033[0m"
    echo -e "\033[31m    -d    build dpdk libary with debug info\033[0m"
    echo -e "\033[31m    -w    specify the work directory prefix, default \"${workdir}\"\033[0m"
    echo -e "\033[31m    -p    specify the dpdk patch directory, default \"${default_patchdir}\"\033[0m"
}

function dpdk_version2tarball()
{
    local version=$1
    echo dpdk-${version}.tar.xz
}

function dpdk_tarball_source_directory()
{
    local tarball=$1

    [ ! -f "$tarball" ] && return 1
    tar -tf ${tarball} | grep '/$' | head -n 1 | sed 's/\///'
}

## parse args
while getopts "hw:p:dv:" OPT; do
    case $OPT in
        v) dpdkver=$OPTARG;;
        w) workdir=$OPTARG ;;
        p) patchdir=$(realpath $OPTARG);;
        d) build_options="${build_options} ${debug_options}";;
        ?) help;exit 1;;
    esac
done

[ -f $workdir ] && echo -e "\033[31mError: work diretory \"${workdir}\" is a regular file\033[0m" && exit 1
[ ! -d $workdir ] && mkdir -p $workdir
workdir=$(realpath $workdir)
echo -e "\033[32musing work directory: $workdir\033[0m"

predir=$(pwd)
pushd $workdir

## prepare dpdk sources
tarball=$(dpdk_version2tarball $dpdkver)
if [ ! -f $tarball ]; then
    wget https://fast.dpdk.org/rel/$tarball -P $workdir
    [ ! -f $tarball ] && echo -e "\033[31mfailed to download \"$tarball\"\033[0m" && exit 1
fi

srcdir=$(dpdk_tarball_source_directory $tarball)
[ -d $workdir/$srcdir ] && echo -e "\033[33mremoving old source directory: $workdir/$srcdir\033[0m" && rm -rf $workdir/$srcdir
tar xf $tarball -C $workdir
[ ! -d $workdir/$srcdir ] && echo -e "\033[31m dpdk source diretory \"$workdir/$srcdir\" not found\033[0m" && exit 1

## patch dpdk
[ -z "$patchdir" ] && patchdir=$(realpath "$predir/patch/$srcdir")
[ ! -d "$patchdir" ] && echo -e "\033[31mError: dpdk patch directory \"${patchdir}\" not exist\033[0m" && exit 1
echo -e "\033[32musing dpdk patch directory: $patchdir\033[0m"

for patchfile in $(ls $patchdir)
do
    patch -p1 -d $workdir/$srcdir < $patchdir/$patchfile
    [ $? -ne 0 ] && echo -e "\033[31mfailed to patch: $patchfile\033[0m" && exit 1
    echo -e "\033[32msucceed to patch: $patchfile\033[0m"
done

## build dpdk and install
echo -e "\033[32mbuild options: $build_options\033[0m"

[ -d dpdkbuild ] && rm -rf dpdkbuild/* ||  mkdir dpdkbuild
[ -d dpdklib ] && rm -rf dpdklib/* || mkdir dpdklib

meson $build_options -Dprefix=$(pwd)/dpdklib $srcdir dpdkbuild

ninja -C dpdkbuild
[ $? -ne 0 ] && echo -e "\033[31mfail to build dpdk\033[0m" && exit 1
ninja -C dpdkbuild install
[ $? -ne 0 ] && echo -e "\033[31mfail to install dpdk\033[0m" && exit 1

kni=dpdkbuild/kernel/linux/kni/rte_kni.ko
[ -f $kni ] && install -m 644 $kni dpdklib

echo -e "DPDK library installed successfully into directory: \033[32m${workdir}/dpdklib\033[0m"

## export dpdk lib
echo -e "You can use this library in dpvs by running the command below:"
echo -e "\033[32m"
echo -e "export PKG_CONFIG_PATH=$(find $(pwd) -name pkgconfig)"
echo -e "\033[0m"

popd
