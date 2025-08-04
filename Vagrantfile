# -*- mode: ruby -*-
# vi: set ft=ruby :

# Automated creation of testing environments / binaries on misc. platforms

$cpus = Integer(ENV.fetch('VMCPUS', '16'))  # create VMs with that many cpus
$xdistn = Integer(ENV.fetch('XDISTN', '16'))  # dispatch tests to that many pytest workers
$wmem = $xdistn * 256  # give the VM additional memory for workers [MB]

def packages_debianoid(user)
  return <<-EOF
    export DEBIAN_FRONTEND=noninteractive
    # this is to avoid grub asking about which device it should install to:
    echo "set grub-pc/install_devices /dev/sda" | debconf-communicate
    apt-get -y -qq update
    apt-get -y -qq dist-upgrade
    # for building borgbackup and dependencies:
    apt install -y libssl-dev libacl1-dev liblz4-dev libzstd-dev pkg-config
    apt install -y libfuse-dev fuse || true
    apt install -y libfuse3-dev fuse3 || true
    apt install -y locales || true
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
    # for building borgbackup and dependencies:
    pkg install -y liblz4 zstd pkgconf
    pkg install -y fusefs-libs || true
    pkg install -y fusefs-libs3 || true
    pkg install -y git bash  # fakeroot causes lots of troubles on freebsd
    # for building python (for the tests we use pyenv built pythons):
    pkg install -y python38 py38-sqlite3
    # make sure there is a python3 command
    ln -sf /usr/local/bin/python3.8 /usr/local/bin/python3
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
    pkg_add bash
    chsh -s bash vagrant
    pkg_add xxhash
    pkg_add lz4
    pkg_add zstd
    pkg_add git  # no fakeroot
    pkg_add openssl%1.1
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
    pkg_add bash
    chsh -s bash vagrant
    echo "export PROMPT_COMMAND=" >> ~vagrant/.bash_profile  # bug in netbsd 9.2, .bash_profile broken for screen
    echo "export PROMPT_COMMAND=" >> ~root/.bash_profile  # bug in netbsd 9.2, .bash_profile broken for screen
    pkg_add pkg-config
    # pkg_add fuse  # llfuse supports netbsd, but is still buggy.
    # https://bitbucket.org/nikratio/python-llfuse/issues/70/perfuse_open-setsockopt-no-buffer-space
    pkg_add python38 py38-sqlite3 py38-pip py38-virtualenv py38-expat
    pkg_add python39 py39-sqlite3 py39-pip py39-virtualenv py39-expat
    pkg_add py310-sqlite3 py310-pip py310-virtualenv py310-expat
    ln -s /usr/pkg/bin/python3.9 /usr/pkg/bin/python
    ln -s /usr/pkg/bin/python3.9 /usr/pkg/bin/python3
    ln -s /usr/pkg/bin/pip3.9 /usr/pkg/bin/pip
    ln -s /usr/pkg/bin/pip3.9 /usr/pkg/bin/pip3
    ln -s /usr/pkg/bin/virtualenv-3.9 /usr/pkg/bin/virtualenv
    ln -s /usr/pkg/bin/virtualenv-3.9 /usr/pkg/bin/virtualenv3
  EOF
end

def packages_darwin
  return <<-EOF
    # install all the (security and other) updates
    sudo softwareupdate --ignore iTunesX
    sudo softwareupdate --ignore iTunes
    sudo softwareupdate --ignore Safari
    sudo softwareupdate --ignore "Install macOS High Sierra"
    sudo softwareupdate --install --all
    which brew || CI=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
    brew update > /dev/null
    brew install pkg-config readline openssl@1.1 zstd lz4 xz xxhash
    brew install --cask macfuse
    # brew upgrade  # upgrade everything (takes rather long)
    echo 'export PKG_CONFIG_PATH=/usr/local/opt/openssl@1.1/lib/pkgconfig' >> ~vagrant/.bash_profile
  EOF
end

def packages_openindiana
  return <<-EOF
    # needs separate provisioning step + reboot:
    #pkg update
    pkg install gcc-13 git pkg-config libxxhash
    ln -sf /usr/bin/python3.9 /usr/bin/python3
    python3 -m ensurepip
    ln -sf /usr/bin/pip3.9 /usr/bin/pip3
    pip3 install virtualenv
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

def fix_pyenv_darwin(boxname)
  return <<-EOF
    echo 'export PYTHON_CONFIGURE_OPTS="--enable-framework"' >> ~/.bash_profile
  EOF
end

def install_pythons(boxname)
  return <<-EOF
    . ~/.bash_profile
    pyenv install 3.12.0  # tests, version supporting openssl 1.1
    pyenv install 3.11.1  # tests, version supporting openssl 1.1
    pyenv install 3.10.2  # tests, version supporting openssl 1.1
    pyenv install 3.9.23  # tests, version supporting openssl 1.1, binary build
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
    # use the latest 3.9 release
    pyenv global 3.9.23
    pyenv virtualenv 3.9.23 borg-env
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
    python setup.py clean
    python setup.py clean2
    pip install -e .[#{fuse}]
  EOF
end

def install_pyinstaller()
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    pip install 'pyinstaller==4.10'
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
      pyenv global 3.9.23 3.10.2 3.11.1 3.12.0
      pyenv local 3.9.23 3.10.2 3.11.1 3.12.0
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

  config.vm.define "focal64" do |b|
    b.vm.box = "ubuntu/focal64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("focal64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("focal64", ".*none.*")
  end

  config.vm.define "jammy64" do |b|
    b.vm.box = "ubuntu/jammy64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("jammy64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("jammy64", ".*none.*")
  end

  config.vm.define "bookworm64" do |b|
    b.vm.box = "debian/bookworm64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("bookworm64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("bookworm64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("bookworm64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("bookworm64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("bookworm64", ".*none.*")
  end

  config.vm.define "bullseye64" do |b|
    b.vm.box = "debian/bullseye64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("bullseye64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("bullseye64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("bullseye64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("bullseye64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("bullseye64", ".*none.*")
  end

  config.vm.define "buster64" do |b|
    b.vm.box = "debian/buster64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("buster64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("buster64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("buster64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("buster64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("buster64", ".*none.*")
  end

  config.vm.define "stretch64" do |b|
    b.vm.box = "generic/debian9"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("stretch64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("stretch64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("stretch64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("stretch64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("stretch64", ".*(fuse3|none).*")
  end

  config.vm.define "freebsd64" do |b|
    b.vm.box = "generic/freebsd13"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.ssh.shell = "sh"
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages freebsd", :type => :shell, :inline => packages_freebsd
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("freebsd64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("freebsd64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("freebsd64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("freebsd64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("freebsd64", ".*(fuse3|none).*")
  end

  config.vm.define "openbsd64" do |b|
    b.vm.box = "generic/openbsd7"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages openbsd", :type => :shell, :inline => packages_openbsd
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("openbsd64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("nofuse")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("openbsd64", ".*fuse.*")
  end

  config.vm.define "netbsd64" do |b|
    b.vm.box = "generic/netbsd9"
    b.vm.provider :virtualbox do |v|
      v.memory = 4096 + $wmem  # need big /tmp tmpfs in RAM!
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages netbsd", :type => :shell, :inline => packages_netbsd
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("netbsd64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(false)
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("netbsd64", ".*fuse.*")
  end

  config.vm.define "darwin64" do |b|
    b.vm.box = "macos-sierra"
    b.vm.provider :virtualbox do |v|
      v.memory = 4096 + $wmem
      v.customize ['modifyvm', :id, '--ostype', 'MacOS_64']
      v.customize ['modifyvm', :id, '--paravirtprovider', 'default']
      v.customize ['modifyvm', :id, '--nested-hw-virt', 'on']
      # Adjust CPU settings according to
      # https://github.com/geerlingguy/macos-virtualbox-vm
      v.customize ['modifyvm', :id, '--cpuidset',
                   '00000001', '000306a9', '00020800', '80000201', '178bfbff']
      # Disable USB variant requiring Virtualbox proprietary extension pack
      v.customize ["modifyvm", :id, '--usbehci', 'off', '--usbxhci', 'off']
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages darwin", :type => :shell, :privileged => false, :inline => packages_darwin
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("darwin64")
    b.vm.provision "fix pyenv", :type => :shell, :privileged => false, :inline => fix_pyenv_darwin("darwin64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("darwin64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("darwin64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("llfuse")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("darwin64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("darwin64", ".*(fuse3|none).*")
  end

  # rsync on openindiana has troubles, does not set correct owner for /vagrant/borg and thus gives lots of
  # permission errors. can be manually fixed in the VM by: sudo chown -R vagrant /vagrant/borg ; then rsync again.
  config.vm.define "openindiana64" do |b|
    b.vm.box = "openindiana/hipster"
    b.vm.provider :virtualbox do |v|
      v.memory = 2048 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages openindiana", :type => :shell, :inline => packages_openindiana
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("openindiana64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("nofuse")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("openindiana64", ".*fuse.*")
  end

  # TODO: create more VMs with python 3.8+ and openssl 1.1.
  # See branch 1.1-maint for a better equipped Vagrantfile (but still on py35 and openssl 1.0).
end
