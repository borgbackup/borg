. ~/.bash_profile
cd /vagrant/borg/borg
. ../borg-env/bin/activate
if which pyenv > /dev/null; then
  # for testing, use the earliest point releases of the supported python versions:
  pyenv global 3.4.0 3.5.0
fi
# otherwise: just use the system python

bold_out=$(tput bold)
blue_out=$(tput setaf 4)
red_out=$(tput setaf 1)
normal_out=$(tput sgr0)

testing_partition_size=64M
root_testing_dir="/var/tmp/borg-tests" # Also hardcoded in server configs in this directory
mkdir -p "$root_testing_dir/rootfs"
if [[ "$(uname -s)" == "Darwin" ]]; then
  mount_base="/Volumes/borg-tests"
else
  mount_base="/mnt/borg-tests"
fi
mkdir -p "$mount_base"

# The directories variable is a bit odd
# In addition to directories, is specifies env variables to be set to "true"
# The environment variables are equal sign seperated, and cannot begin with /
# The directory must start with / and come last, because of that it can have equal signs
# If we had guarenteed Bash 4 support, we could use associative arrays
# However, it isn't on OS X and probably won't come due to licensing issues
directories=("$root_testing_dir/rootfs")

if [[ "$(uname -s)" == "Darwin" ]]; then
  # No /proc, very limited FS support (pretty much just the root, /tmp, and fuse)
  directories+=("$TMPDIR")
  filesystems="fuse"
else
  test_mount_point="$(df -P "$root_testing_dir" | awk 'END{print $NF}')" # /var could be mounted to a different FS type
  root_fs="$(grep -oP '^[^ ]* '"$test_mount_point"' \K[^ ]*' /proc/mounts | tail -n 1)"

  # /proc/filesystems specifies which filesystems *are* loaded
  # Directories in /lib/modules/$(uname -r)/kernel/fs specify which filesystems *can* be loaded
  # We want both
  filesystems="$((cut -d'	' -f2 /proc/filesystems; find "/lib/modules/$(uname -r)/kernel/fs/" -mindepth 1 -maxdepth 1 -type d -printf "%f\n") | sort -u)"
fi

if id "vagrant" >/dev/null 2>&1; then
  ssh_user="vagrant"
elif id "ubuntu" >/dev/null 2>&1; then
  ssh_user="ubuntu"
elif [[ "$SUDO_USER" ]] && [[ "$SUDO_USER" != root ]]; then
  ssh_user="$SUDO_USER"
  >&2 echo "${bold_out}${blue_out}It looks like this is a host dev environment not a Vagrant environment"
  >&2 echo "Using user $ssh_user for SSH${normal_out}"
else
  ssh_user="root"
  >&2 echo "${bold_out}${red_out}Warning: no suitable SSH user found, using root{normal_out}"
  exit 1
fi

function cleanup() {
  # We use a loop because umount short-circuits on a failure
  for dir in "$mount_base"/*; do
    [[ -d "$dir" ]] && umount "$dir"
  done
  # kill after umount in cases of networked servers
  kill $(cat "$root_testing_dir"/*.pid 2> /dev/null) 2> /dev/null # Only outputs errors if no PID files found
  rm -r "$mount_base"
  rm -r "$root_testing_dir"
}

function error() {
  >&2 echo "${bold_out}${red_out}Error while preparing filesystem type $1, aborting${normal_out}"
  cleanup
  exit 1
}

while read filesystem; do
  [[ "$filesystem" == "$root_fs" ]] && continue
  case "$filesystem" in
    tmpfs)
      mkdir "$mount_base/tmpfs"
      mount -t tmpfs tmpfs "$mount_base/tmpfs" -o "size=$testing_partition_size" || error tmpfs
      directories+=("$mount_base/tmpfs")
      ;;
    ext4 | xfs)
      truncate -s "$testing_partition_size" "$root_testing_dir/$filesystem"
      force_option="-F"
      if [[ "$filesystem" == "xfs" ]]; then
        force_option="-f"
      fi
      "mkfs.$filesystem" "$force_option" "$root_testing_dir/$filesystem" || error "$filesystem"
      mkdir "$mount_base/$filesystem"
      mount -t "$filesystem" "$root_testing_dir/$filesystem" "$mount_base/$filesystem" || error "$filesystem"
      directories+=("$mount_base/$filesystem")
      ;;
    cifs)
      continue # Breaks py.test (I think). Reenable if working.
      mkdir "$root_testing_dir/cifs"
      chown nobody "$root_testing_dir/cifs" # guest == nobody user
      smbd -D -s vagrant-tools/smb.conf
      mkdir "$mount_base/cifs"
      # smbd exits before startup
      if which nc > /dev/null && [[ "$(readlink "$(which nc)")" != "ncat" ]]; then
        while ! nc -z localhost 10445; do
          sleep 0.5
        done
      else
        while ! bash -c 'cat < /dev/null > /dev/tcp/localhost/10445' 2> /dev/null; do
          sleep 0.5
        done
      fi
      mount -t cifs //localhost/share "$mount_base/cifs" -o "port=10445,credentials=$PWD/vagrant-tools/smbcredentials" || error CIFS
      directories+=("$mount_base/cifs")
      ;;
    fuse)
      fuse_supported=true
      ;;
  esac
done <<< "$filesystems"

if [[ "$fuse_supported" ]]; then
  if which sshfs > /dev/null; then
    mkdir "$root_testing_dir/sshfs"
    chown "$ssh_user" "$root_testing_dir/sshfs"
    ssh-keygen -t rsa -b 2048 -C 'borgbackup@github.com' -N '' -f "$root_testing_dir/ssh_key"
    "$(which sshd)" -f vagrant-tools/sshd_config
    mkdir "$mount_base/sshfs"
    sshfs "$ssh_user@localhost:$root_testing_dir/sshfs" "$mount_base/sshfs" \
      -p 10022 \
      -o "IdentityFile=$root_testing_dir/ssh_key" \
      -o "StrictHostKeyChecking=no" \
      || error SSHFS
    directories+=("$mount_base/sshfs")
  fi
  if which ntfs-3g > /dev/null; then
    truncate -s 128M "$root_testing_dir/ntfs" # NTFS requires a larger partition size than most filesystems
    mkfs.ntfs -F "$root_testing_dir/ntfs" || error NTFS
    mkdir "$mount_base/ntfs"
    ntfs-3g "$root_testing_dir/ntfs" "$mount_base/ntfs" || error NTFS
    directories+=("BORG_TESTS_IGNORE_MODES=$mount_base/ntfs")
  fi
fi

for directory in "${directories[@]}"; do
  env=()
  while true; do
    if [[ "$directory" == /* ]]; then # That's not a filesystem glob (just checks if it starts with /)
      break
    fi
    index="$(expr index "$directory" =)"
    if [[ "$index" -eq 0 ]]; then
      >&2 echo "${bold_out}${red_out}Warning: malformed directory in test driver${normal_out}"
      break
    fi
    env+=("${directory:0:$(($index-1))}=true")
    directory="${directory:$index}"
  done
  echo "${bold_out}${blue_out}Running tests in $directory${normal_out}"
  env+=("TMPDIR=$directory")
  if ! env -- "${env[@]}" tox --skip-missing-interpreters; then
    >&2 echo "${bold_out}${red_out}Tests failed in $directory, aborting${normal_out}"
    cleanup
    exit 1
  fi
done

cleanup
exit 0
