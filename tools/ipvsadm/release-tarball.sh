#!/bin/bash
#
# Script for making a release tarball, where we avoid including files
# not related to the git repository, by using git archive to a temp
# dir (mktemp).
#
# You need to create a git tag corrosponding with the version in the
# file VERSION, before you can make a release.  For testing purposes,
# its possible to give a commit id on the command line via "-c" option.
#
# The script also creates a GPG signed file output of the uncompressed
# tarball (which is needed by kernel.org upload utility).  A specific
# GPGKEY ID can be specified on the command line via "-g" option.
#
# The release tarballs and GPG signing files are placed in the
# directory "release/".
#
set -e
NAME=ipvsadm
#PREV_VERSION=1.xx # disabled in script

if [ -e VERSION ]; then
    export VERSION=$(cat VERSION)
else
    echo "ERROR - Cannot find version file"
    exit 1
fi
VERSION_TAG="v${VERSION}"
# Notice VERSION can be overridden by command line arg -c

##  --- Parse command line arguments ---
while getopts "c:g:" option; do
    case $option in
	c)
	    COMMIT=$OPTARG
	    echo "[WARNING] using git commit/id ($COMMIT) instead of release tag"
	    VERSION=$COMMIT
	    VERSION_TAG=$COMMIT
	    git show $COMMIT > /dev/null
	    ;;
	g)
	    SPECIFIC_GPGKEY=$OPTARG
	    echo "[NOTICE] Using GPG signing key: $SPECIFIC_GPGKEY"
	    gpg --list-key "$SPECIFIC_GPGKEY" > /dev/null
	    ;;
	?|*)
	    echo ""
	    echo "[ERROR] Unknown parameter \"$OPTARG\""
	    exit 2
    esac
done
shift $[ OPTIND - 1 ]

if [ -n "$SPECIFIC_GPGKEY" ]; then
    GPGKEY="-u $SPECIFIC_GPGKEY"
fi

echo "Creating tarball for release tag: $VERSION_TAG"
echo "================================="

read -p "Are you sure, you want to create a release tarball (y/n)? " -n 1 -r
echo ""
if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
    exit 1
fi

# Create a unique tempdir, to avoid leftovers from older release builds
TMPDIR=`mktemp -dt $NAME.XXXXXXXXXX`
trap 'rm -rf $TMPDIR' EXIT
#echo "TMPDIR:$TMPDIR"
PKGDIR="$TMPDIR/${NAME}-${VERSION}"
#echo PKGDIR:$PKGDIR
RELDIR=release
if [ ! -d $RELDIR ]; then
    mkdir -p $RELDIR
fi

# Compression packer tool
packer=gzip
packext=gz

TARBALL="$RELDIR/$NAME-$VERSION.tar";
#CHANGES="$RELDIR/changes-$NAME-$PREV_VERSION-$VERSION.txt";

#mkdir -p "$TMPDIR"
#echo " -- Git shortlog v$PREV_VERSION..$VERSION_TAG"
#git shortlog "v$PREV_VERSION..$VERSION_TAG" > "$CHANGES"

echo " -- Git archiving version tag $VERSION_TAG"
git archive --prefix="$NAME-$VERSION/" "$VERSION_TAG" | tar -xC "$TMPDIR/"

#pushd "$PKGDIR" > /dev/null && {
#    echo " -- Generating configure scripts..."
#    sh autogen.sh
#    popd > /dev/null
#}

# Create .spec file
export RELEASE=1
if [ -f ipvsadm.spec.in ]; then
    echo " -- Creating .spec file"
    sed -e "s/@@VERSION@@/${VERSION}/g" \
	-e "s/@@RELEASE@@/${RELEASE}/g" \
	< ipvsadm.spec.in > ${PKGDIR}/ipvsadm.spec
fi

echo " -- Creating tarball $TARBALL"
#tar --use=${packer} -C "$TMPDIR" -cf "$TARBALL" "$NAME-$VERSION";
tar -C "$TMPDIR" -cf "$TARBALL" "$NAME-$VERSION";

#(Disabled checksums are auto created by kernel.org kup scripts)
#echo " -- Calculating checksums"
#md5sum "$TARBALL"  > "${TARBALL}.md5sum";
#sha1sum "$TARBALL" > "${TARBALL}.sha1sum";

echo " -- You need to sign the tarball (uncompressed)"
gpg  $GPGKEY --armor --detach-sign "$TARBALL";

echo " -- Compress tarball to ${TARBALL}.${packext}"
${packer} "$TARBALL"

echo "MANUAL: Upload to kernel.org, via command:"
echo kup put ${TARBALL}.${packext} ${TARBALL}.asc /pub/linux/utils/kernel/ipvsadm/
