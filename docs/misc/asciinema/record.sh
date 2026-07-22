#!/bin/sh
# Record the borg 1.4 demo screencast in a container, see README.rst.
#
# Usage: ./record.sh [output directory]
#
# Set ENGINE=docker if you do not want to use podman.
set -eu

# The borg release the screencast is recorded with: borg is built from this git
# tag and the tag is what borg --version shows in the screencast. Update it for
# every screencast we publish. Use BORG_VERSION=HEAD (or export it in your
# environment) to record from your work tree while working on the demo.
BORG_VERSION="${BORG_VERSION:-1.4.5}"

cd "$(dirname "$0")"
OUTDIR=$(cd "${1:-.}" && pwd)

ENGINE=${ENGINE:-podman}
command -v "$ENGINE" > /dev/null || { echo "$ENGINE not found, set ENGINE=docker?" >&2; exit 1; }

ROOT=$(git rev-parse --show-toplevel)
git -C "$ROOT" rev-parse --verify --quiet "$BORG_VERSION^{commit}" > /dev/null || {
    echo "no such git tag / commit: $BORG_VERSION - tag the release first?" >&2; exit 1; }

# The exported sources have no .git, so we have to tell setuptools-scm the
# version. For HEAD that is something like 1.4.5.dev42+g0123456.
if [ "$BORG_VERSION" = HEAD ]; then
    VERSION=$(git -C "$ROOT" describe --tags --match '[0-9]*' \
              | sed -e 's/-\([0-9]*\)-g\([0-9a-f]*\)$/.dev\1+g\2/')
else
    VERSION="$BORG_VERSION"
fi

# Build the image from a clean context: the borg sources of that tag plus the
# scripts in this directory (and not the whole, possibly dirty, work tree).
CONTEXT=$(mktemp -d)
trap 'rm -rf "$CONTEXT"' EXIT
git -C "$ROOT" archive --format=tar --prefix=borg/ "$BORG_VERSION" > "$CONTEXT/borg-src.tar"
cp Containerfile demo.tcl demo-data.py record.exp entrypoint.sh "$CONTEXT/"

echo "recording with borg $VERSION"
$ENGINE build -t borg14-demo-screencast --build-arg "BORG_VERSION=$VERSION" "$CONTEXT"

# --device /dev/fuse and SYS_ADMIN are needed for the "borg mount" part.
# Without label=disable, the files we back up have a security.selinux xattr,
# which borg extract then complains about (in the middle of the screencast).
$ENGINE run --rm -t \
    --hostname host \
    --device /dev/fuse --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined --security-opt label=disable \
    -v "$OUTDIR:/out" \
    borg14-demo-screencast

echo
echo "Play it:   asciinema play $OUTDIR/borg14-demo.cast"
echo "Upload it: asciinema upload $OUTDIR/borg14-demo.cast"
