# -*- mode: ruby -*-
# vi: set ft=ruby :

# Automated creation of testing environments / binaries on misc. platforms

$cpus = Integer(ENV.fetch('VMCPUS', '16'))  # create VMs with that many cpus
$xdistn = Integer(ENV.fetch('XDISTN', '16'))  # dispatch tests to that many pytest workers
$wmem = $xdistn * 256  # give the VM additional memory for workers [MB]

def packages_debianoid(user)
  return <<-EOF
    export DEBIAN_FRONTEND=noninteractive
    # This is to avoid GRUB asking which device it should install to:
    echo "set grub-pc/install_devices /dev/sda" | debconf-communicate
    apt-get -y -qq update
    apt-get -y -qq dist-upgrade
    # For building BorgBackup and dependencies:
    apt install -y libssl-dev libacl1-dev liblz4-dev libzstd-dev libxxhash-dev pkg-config
    apt install -y libfuse-dev fuse || true
    apt install -y libfuse3-dev fuse3 || true
    apt install -y locales || true
    # We need to give the prefix to support Debian Buster (no libxxhash.pc for pkg-config there):
    echo 'export BORG_LIBXXHASH_PREFIX=/usr' >> ~vagrant/.bash_profile
    sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen
    usermod -a -G fuse #{user}
    chgrp fuse /dev/fuse
    chmod 666 /dev/fuse
    apt install -y fakeroot build-essential git curl
    apt install -y python3-dev python3-setuptools virtualenv
    # for building python:
    apt install -y zlib1g-dev libbz2-dev libncurses5-dev libreadline-dev liblzma-dev libsqlite3-dev libffi-dev
  EOF
end

def packages_freebsd
  return <<-EOF
    # in case the VM has no hostname set
    hostname freebsd
    # install all the (security and other) updates, base system
    freebsd-update --not-running-from-cron fetch install
    # For building BorgBackup and dependencies:
    pkg install -y liblz4 zstd pkgconf
    pkg install -y fusefs-libs || true
    pkg install -y fusefs-libs3 || true
    pkg install -y rust
    pkg install -y git bash  # fakeroot causes lots of troubles on freebsd
    # for building python (for the tests we use pyenv built pythons):
    pkg install -y python310 py310-sqlite3
    # make sure there is a python3 command
    ln -sf /usr/local/bin/python3.10 /usr/local/bin/python3
    python3 -m ensurepip
    pip3 install virtualenv
    # make bash default / work:
    chsh -s bash vagrant
    mount -t fdescfs fdesc /dev/fd
    echo 'fdesc        /dev/fd         fdescfs         rw      0       0' >> /etc/fstab
    # make FUSE work
    echo 'fuse_load="YES"' >> /boot/loader.conf
    echo 'vfs.usermount=1' >> /etc/sysctl.conf
    kldload fusefs
    sysctl vfs.usermount=1
    pw groupmod operator -M vagrant
    # /dev/fuse has group operator
    chmod 666 /dev/fuse
    # install all the (security and other) updates, packages
    pkg update
    yes | pkg upgrade
    echo 'export BORG_OPENSSL_PREFIX=/usr' >> ~vagrant/.bash_profile
  EOF
end

def packages_openbsd
  return <<-EOF
    hostname "openbsd77.localdomain"
    echo "$(hostname)" > /etc/myname
    echo "127.0.0.1	localhost" > /etc/hosts
    echo "::1 localhost" >> /etc/hosts
    echo "127.0.0.1	$(hostname) $(hostname -s)" >> /etc/hosts
    echo "https://ftp.eu.openbsd.org/pub/OpenBSD" > /etc/installurl
    ftp https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/$(uname -m)/comp$(uname -r | tr -d .).tgz
    tar -C / -xzphf comp$(uname -r | tr -d .).tgz
    rm comp$(uname -r | tr -d .).tgz
    pkg_add bash
    chsh -s bash vagrant
    pkg_add xxhash
    pkg_add lz4
    pkg_add zstd
    pkg_add git  # no fakeroot
    pkg_add rust
    pkg_add openssl%3.4
    pkg_add py3-pip
    pkg_add py3-virtualenv
  EOF
end

def packages_netbsd
  return <<-EOF
    echo 'http://ftp.NetBSD.org/pub/pkgsrc/packages/NetBSD/$arch/9.3/All' > /usr/pkg/etc/pkgin/repositories.conf
    pkgin update
    pkgin -y upgrade
    pkg_add zstd lz4 xxhash git
    pkg_add rust
    pkg_add bash
    chsh -s bash vagrant
    echo "export PROMPT_COMMAND=" >> ~vagrant/.bash_profile  # bug in netbsd 9.2, .bash_profile broken for screen
    echo "export PROMPT_COMMAND=" >> ~root/.bash_profile  # bug in netbsd 9.2, .bash_profile broken for screen
    pkg_add pkg-config
    # pkg_add fuse  # llfuse supports netbsd, but is still buggy.
    # https://bitbucket.org/nikratio/python-llfuse/issues/70/perfuse_open-setsockopt-no-buffer-space
    pkg_add py311-sqlite3 py311-pip py311-virtualenv py311-expat
    ln -s /usr/pkg/bin/python3.11 /usr/pkg/bin/python
    ln -s /usr/pkg/bin/python3.11 /usr/pkg/bin/python3
    ln -s /usr/pkg/bin/pip3.11 /usr/pkg/bin/pip
    ln -s /usr/pkg/bin/pip3.11 /usr/pkg/bin/pip3
    ln -s /usr/pkg/bin/virtualenv-3.11 /usr/pkg/bin/virtualenv
    ln -s /usr/pkg/bin/virtualenv-3.11 /usr/pkg/bin/virtualenv3
  EOF
end

def package_update_openindiana
  return <<-EOF
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    # needs separate provisioning step + reboot to become effective:
    pkg update
  EOF
end

def packages_openindiana
  return <<-EOF
    pkg install gcc-13 git
    pkg install pkg-config libxxhash
    pkg install python-313
    ln -sf /usr/bin/python3.13 /usr/bin/python3
    ln -sf /usr/bin/python3.13-config /usr/bin/python3-config
    python3 -m ensurepip
    ln -sf /usr/bin/pip3.13 /usr/bin/pip3
    pip3 install virtualenv
    # let borg's pkg-config find openssl:
    pfexec pkg set-mediator -V 3 openssl
  EOF
end

def install_pyenv(boxname)
  return <<-EOF
    echo 'export PYTHON_CONFIGURE_OPTS="--enable-shared"' >> ~/.bash_profile
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bash_profile
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bash_profile
    . ~/.bash_profile
    curl -s -L https://raw.githubusercontent.com/yyuu/pyenv-installer/master/bin/pyenv-installer | bash
    echo 'eval "$(pyenv init --path)"' >> ~/.bash_profile
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc
    echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc
  EOF
end

def install_pythons(boxname)
  return <<-EOF
    . ~/.bash_profile
    pyenv install 3.11.14  # tests, binary build
    pyenv rehash
  EOF
end

def build_sys_venv(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    virtualenv --python=python3 borg-env
  EOF
end

def build_pyenv_venv(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    # use the latest 3.11 release
    pyenv global 3.11.14
    pyenv virtualenv 3.11.14 borg-env
    ln -s ~/.pyenv/versions/borg-env .
  EOF
end

def install_borg(fuse)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    pip install -U wheel  # upgrade wheel, might be too old
    cd borg
    pip install -r requirements.d/development.lock.txt
    python3 scripts/make.py clean
    pip install -e .[#{fuse}]
  EOF
end

def install_pyinstaller()
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    pip install 'pyinstaller==6.7.0'
  EOF
end

def build_binary_with_pyinstaller(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    cd borg
    pyinstaller --clean --distpath=/vagrant/borg scripts/borg.exe.spec
    echo 'export PATH="/vagrant/borg:$PATH"' >> ~/.bash_profile
    cd .. && tar -czvf borg.tgz borg-dir
  EOF
end

def run_tests(boxname, skip_env)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg/borg
    . ../borg-env/bin/activate
    if which pyenv 2> /dev/null; then
      # for testing, use the earliest point releases of the supported python versions:
      pyenv global 3.11.14
      pyenv local 3.11.14
    fi
    # otherwise: just use the system python
    # avoid that git complains about dubious ownership if we use fakeroot:
    git config --global --add safe.directory /vagrant/borg/borg
    # some OSes can only run specific test envs, e.g. because they miss FUSE support:
    export TOX_SKIP_ENV='#{skip_env}'
    if which fakeroot 2> /dev/null; then
      echo "Running tox WITH fakeroot -u"
      fakeroot -u tox --skip-missing-interpreters
    else
      echo "Running tox WITHOUT fakeroot -u"
      tox --skip-missing-interpreters
    fi
  EOF
end

def fs_init(user)
  return <<-EOF
    # clean up (wrong/outdated) stuff we likely got via rsync:
    rm -rf /vagrant/borg/borg/.tox 2> /dev/null
    rm -rf /vagrant/borg/borg/borgbackup.egg-info 2> /dev/null
    rm -rf /vagrant/borg/borg/__pycache__ 2> /dev/null
    find /vagrant/borg/borg/src -name '__pycache__' -exec rm -rf {} \\; 2> /dev/null
    chown -R #{user} /vagrant/borg
    touch ~#{user}/.bash_profile ; chown #{user} ~#{user}/.bash_profile
    echo 'export LANG=en_US.UTF-8' >> ~#{user}/.bash_profile
    echo 'export LC_CTYPE=en_US.UTF-8' >> ~#{user}/.bash_profile
    echo 'export XDISTN=#{$xdistn}' >> ~#{user}/.bash_profile
  EOF
end

Vagrant.configure(2) do |config|
  # use rsync to copy content to the folder
  config.vm.synced_folder ".", "/vagrant/borg/borg", :type => "rsync", :rsync__args => ["--verbose", "--archive", "--delete", "--exclude", ".python-version"], :rsync__chown => false
  # do not let the VM access . on the host machine via the default shared folder!
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider :virtualbox do |v|
    #v.gui = true
    v.cpus = $cpus
  end

  config.vm.define "noble" do |b|
    b.vm.box = "bento/ubuntu-24.04"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("noble")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("noble", ".*none.*")
  end

  config.vm.define "jammy" do |b|
    b.vm.box = "ubuntu/jammy64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("jammy")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("jammy", ".*none.*")
  end

  config.vm.define "trixie" do |b|
    b.vm.box = "debian/testing64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("trixie")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("trixie")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("trixie")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("trixie")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("trixie", ".*none.*")
  end

  config.vm.define "bookworm" do |b|
    b.vm.box = "debian/bookworm64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("bookworm")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("bookworm")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("bookworm")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("bookworm")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("bookworm", ".*none.*")
  end

  config.vm.define "bullseye" do |b|
    b.vm.box = "debian/bullseye64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("bullseye")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("bullseye")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("bullseye")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("bullseye")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("bullseye", ".*none.*")
  end

  config.vm.define "freebsd13" do |b|
    b.vm.box = "generic/freebsd13"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.ssh.shell = "sh"
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages freebsd", :type => :shell, :inline => packages_freebsd
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("freebsd13")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("freebsd13")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("freebsd13")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("freebsd13")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("freebsd13", ".*(fuse3|none).*")
  end

  config.vm.define "freebsd14" do |b|
    b.vm.box = "generic/freebsd14"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.ssh.shell = "sh"
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages freebsd", :type => :shell, :inline => packages_freebsd
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("freebsd14")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("freebsd14")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("freebsd14")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("freebsd14")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("freebsd14", ".*(fuse3|none).*")
  end

  config.vm.define "openbsd7" do |b|
    b.vm.box = "l3system/openbsd77-amd64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages openbsd", :type => :shell, :inline => packages_openbsd
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("openbsd7")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("nofuse")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("openbsd7", ".*fuse.*")
  end

  config.vm.define "netbsd9" do |b|
    b.vm.box = "generic/netbsd9"
    b.vm.provider :virtualbox do |v|
      v.memory = 4096 + $wmem  # need big /tmp tmpfs in RAM!
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages netbsd", :type => :shell, :inline => packages_netbsd
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("netbsd9")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(false)
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("netbsd9", ".*fuse.*")
  end

  # rsync on openindiana has troubles, does not set correct owner for /vagrant/borg and thus gives lots of
  # permission errors. can be manually fixed in the VM by: sudo chown -R vagrant /vagrant/borg ; then rsync again.
  config.vm.define "openindiana" do |b|
    b.vm.box = "openindiana/hipster"
    b.vm.provider :virtualbox do |v|
      v.memory = 2048 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "package update openindiana", :type => :shell, :inline => package_update_openindiana, :reboot => true
    b.vm.provision "packages openindiana", :type => :shell, :inline => packages_openindiana
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("openindiana")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("nofuse")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("openindiana", ".*fuse.*")
  end
end
