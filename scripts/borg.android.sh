#! /bin/bash

if [ -z "$1" ] ; then
    echo "Usage: $0 <path to pyinstaller result>"
    exit 1
fi

cd $1

cp -t . \
    /lib/ld-linux-armhf.so.3 \
    /lib/arm-linux-gnueabihf/libc.so.6 \
    /lib/arm-linux-gnueabihf/libm.so.6 \
    /lib/arm-linux-gnueabihf/libpthread.so.0 \
    /lib/arm-linux-gnueabihf/librt.so.1 \
    /lib/arm-linux-gnueabihf/libutil.so.1 \
    /lib/arm-linux-gnueabihf/libdl.so.2

# keep in mind that this script needs to run with the very minimal
# support of an standard android build. So no readlink or anything
# fancy and not even a bash.
cat > borg <<'EOF'
#! /system/bin/sh

ORIGDIR="$(pwd)"
RELPATH="${0%%/borg}"
if ! [ -d "$RELPATH" ] ; then
    echo "$0: can't find installation dir. Use absolute path to help."
    exit 2
fi
cd "$RELPATH"
BORGDIR="$PWD"
cd "$ORIGDIR"

# jump straigt to pass2 because reexec doesn't work with explicit ld.so invocation.
export _MEIPASS2="$BORGDIR"

"$BORGDIR/ld-linux-armhf.so.3" --library-path "$BORGDIR" "$BORGDIR/borg.real" "$@"
EOF

chmod a+x borg

# the bootloader uses the executable name to find it's packaged resources.
# But it can fallback to the executable name plus .pkg
cp borg.real ld-linux-armhf.so.3.pkg
