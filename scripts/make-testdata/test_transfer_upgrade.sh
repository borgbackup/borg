# this scripts uses borg 1.2 to generate test data for "borg transfer --upgrader=From12To20"
BORG=./borg-1.2.2
# on macOS, gnu tar is available as gtar
TAR=gtar
SRC=/tmp/borgtest
ARCHIVE=`pwd`/src/borg/testsuite/archiver/repo12.tar.gz

export BORG_REPO=/tmp/repo12
META=$BORG_REPO/test_meta
export BORG_PASSPHRASE="waytooeasyonlyfortests"
export BORG_DELETE_I_KNOW_WHAT_I_AM_DOING=YES

$BORG init -e repokey 2> /dev/null
mkdir $META

# archive1
mkdir $SRC

pushd $SRC >/dev/null

mkdir directory

echo "content" > directory/no_hardlink

echo "hardlink content" > hardlink1
ln hardlink1 hardlink2

echo "symlinked content" > target
ln -s target symlink

ln -s doesnotexist broken_symlink

mkfifo fifo

touch without_xattrs
touch with_xattrs
xattr -w key1 value with_xattrs
xattr -w key2 ""    with_xattrs

touch without_flags
touch with_flags
chflags nodump with_flags

popd >/dev/null

$BORG create ::archive1 $SRC
$BORG list ::archive1 --json-lines > $META/archive1_list.json
rm -rf $SRC

# archive2
mkdir $SRC

pushd $SRC >/dev/null

sudo mkdir root_stuff
sudo mknod root_stuff/bdev_12_34 b 12 34
sudo mknod root_stuff/cdev_34_56 c 34 56
sudo touch root_stuff/strange_uid_gid  # no user name, no group name for this uid/gid!
sudo chown 54321:54321 root_stuff/strange_uid_gid

popd >/dev/null

$BORG create ::archive2 $SRC
$BORG list ::archive2 --json-lines > $META/archive2_list.json
sudo rm -rf $SRC/root_stuff
rm -rf $SRC


$BORG --version > $META/borg_version.txt
$BORG list :: --json > $META/repo_list.json

pushd $BORG_REPO >/dev/null
$TAR czf $ARCHIVE .
popd >/dev/null

$BORG delete :: 2> /dev/null
