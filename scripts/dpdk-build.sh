#!/bin/env bash
############################################################################
# usage: $0 [-v dpdk-version] [-d] [-w work-directory] [-p patch-directory]

build_options="-Denable_kmods=true"
debug_options="-Dbuildtype=debug -Dc_args=-DRTE_MALLOC_DEBUG"

dpdkver=20.11.10                            # default dpdk version (use stable version)
tarball=dpdk-${dpdkver}.tar.xz
srcdir=dpdk-stable-$dpdkver

workdir=""
patchdir=""

function help()
{
    echo -e "\033[31musage: $0 [-d] [-w work-directory] [-p patch-directory]\033[0m"
    echo -e "\033[31mOPTIONS:\033[0m"
    echo -e "\033[31m    -v    specify the dpdk version, default $dpdkver\033[0m"
    echo -e "\033[31m    -d    build dpdk libary with debug info\033[0m"
    echo -e "\033[31m    -w    specify the work directory prefix, default $(pwd)\033[0m"
    echo -e "\033[31m    -p    specify the dpdk patch directory, default $(pwd)/patch/dpdk-stable-$dpdkver\033[0m"
}

function set_dpdk_version()
{
    dpdkver=$1
    tarball=dpdk-${dpdkver}.tar.xz
    srcdir=dpdk-stable-$dpdkver
}

function set_work_directory()
{
    [ ! -d $1 ] && return 1
    workdir=$(realpath $1)/dpdk
}

function set_patch_directory()
{
    [ ! -d $1 ] && return 1
    patchdir=$(realpath $1)
}

## parse args
while getopts "hw:p:dv:" OPT; do
    case $OPT in
        v) set_dpdk_version $OPTARG;;
        w) set_work_directory $OPTARG ;;
        p) set_patch_directory $OPTARG;;
        d) build_options="${build_options} ${debug_options}";;
        ?) help && exit 1;;
    esac
done

[ -z "$workdir" ] && workdir=$(pwd)/dpdk				# use default work directory
[ -z "$patchdir" ] && patchdir=$(pwd)/patch/dpdk-stable-$dpdkver  	# use default dpdk patch directory

[ ! -d $workdir ] && mkdir $workdir
echo -e "\033[32mwork directory: $workdir\033[0m"

[ ! -d $patchdir ] && echo -e "\033[31mdpdk patch file directory doesn't exist: $patchdir\033[0m" && exit 1
echo -e "\033[32mdpdk patch directory: $patchdir\033[0m"

echo -e "\033[32mbuild options: $build_options\033[0m"

## prepare dpdk sources
cd $workdir
if [ ! -f $tarball ]; then
    wget https://fast.dpdk.org/rel/$tarball -P $workdir
    [ ! -f $tarball ] && echo -e "\033[31mfail to download $tarball\033[0m" && exit 1
fi

[ -d $workdir/$srcdir ] && echo -e "\033[33mremoving old source directory: $workdir/$srcdir\033[0m" && rm -rf $workdir/$srcdir
tar xf $tarball -C $workdir
echo "$(pwd), $workdir, $srcdir"
[ ! -d $workdir/$srcdir ] && echo -e "\033[31m$workdir/$srcdir directory is missing\033[0m" && exit 1

## patch dpdk
for patchfile in $(ls $patchdir)
do
    patch -p1 -d $workdir/$srcdir < $patchdir/$patchfile
    [ $? -ne 0 ] && echo -e "\033[31mfail to patch: $patchfile\033[0m" && exit 1
    echo -e "\033[32msucceed to patch: $patchfile\033[0m"
done

## build dpdk and install
[ -d dpdkbuild ] && rm -rf dpdkbuild/* ||  mkdir dpdkbuild
[ -d dpdklib ] && rm -rf dpdklib/* || mkdir dpdklib

meson $build_options -Dprefix=$(pwd)/dpdklib $srcdir dpdkbuild

ninja -C dpdkbuild
[ $? -ne 0 ] && echo -e "\033[31mfail to build dpdk\033[0m" && exit 1
ninja -C dpdkbuild install
[ $? -ne 0 ] && echo -e "\033[31mfail to install dpdk\033[0m" && exit 1

kni=dpdkbuild/kernel/linux/kni/rte_kni.ko
[ -f $kni ] && install -m 644 $kni dpdklib

echo -e "DPDK library installed successfully into directory: \033[32m$(pwd)/dpdklib\033[0m"

## export dpdk lib
echo -e "You can use this library in dpvs by running the command below:"
echo -e "\033[32m"
echo -e "export PKG_CONFIG_PATH=$(find $(pwd) -name pkgconfig)"
echo -e "\033[0m"
