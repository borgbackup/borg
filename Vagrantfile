# -*- mode: ruby -*-
# vi: set ft=ruby :

# Automated creation of testing environments / binaries on misc. platforms

def packages_prepare_wheezy
  return <<-EOF
      # debian 7 wheezy does not have lz4, but it is available from wheezy-backports:
      echo "deb http://http.debian.net/debian wheezy-backports main" > /etc/apt/sources.list.d/wheezy-backports.list
  EOF
end

def packages_debianoid
  return <<-EOF
    if id "vagrant" >/dev/null 2>&1; then
      username='vagrant'
      home_dir=/home/vagrant
    else
      username='ubuntu'
      home_dir=/home/ubuntu
    fi
    apt-get update
    # install all the (security and other) updates
    apt-get dist-upgrade -y
    # for building borgbackup and dependencies:
    apt-get install -y libssl-dev libacl1-dev liblz4-dev libfuse-dev fuse pkg-config
    usermod -a -G fuse $username
    apt-get install -y fakeroot build-essential git
    apt-get install -y python3-dev python3-setuptools
    # for building python:
    apt-get install -y zlib1g-dev libbz2-dev libncurses5-dev libreadline-dev liblzma-dev libsqlite3-dev
    # filesystem drivers
    apt-get install -y ntfs-3g openssh-server sshfs xfsprogs samba cifs-utils
    # this way it works on older dists (like ubuntu 12.04) also:
    # for python 3.2 on ubuntu 12.04 we need pip<8 and virtualenv<14 as
    # newer versions are not compatible with py 3.2 any more.
    easy_install3 'pip<8.0'
    pip3 install 'virtualenv<14.0'
    touch $home_dir/.bash_profile ; chown $username $home_dir/.bash_profile
  EOF
end

def packages_redhatted
  return <<-EOF
    yum install -y epel-release
    yum update -y
    # for building borgbackup and dependencies:
    yum install -y openssl-devel openssl libacl-devel libacl lz4-devel fuse-devel fuse pkgconfig
    usermod -a -G fuse vagrant
    yum install -y fakeroot gcc git patch
    # needed to compile msgpack-python (otherwise it will use slow fallback code):
    yum install -y gcc-c++
    # for building python:
    yum install -y zlib-devel bzip2-devel ncurses-devel readline-devel xz xz-devel sqlite-devel
    # filesystem drivers
    yum install -y ntfs-3g openssh fuse-sshfs xfsprogs samba cifs-utils ntfsprogs
    #yum install -y python-pip
    #pip install virtualenv
    touch ~vagrant/.bash_profile ; chown vagrant ~vagrant/.bash_profile
  EOF
end

def packages_darwin
  return <<-EOF
    # install all the (security and other) updates
    sudo softwareupdate --install --all
    # get osxfuse 3.x pre-release code from github:
    curl -s -L https://github.com/osxfuse/osxfuse/releases/download/osxfuse-3.4.1/osxfuse-3.4.1.dmg >osxfuse.dmg
    MOUNTDIR=$(echo `hdiutil mount osxfuse.dmg | tail -1 | awk '{$1="" ; print $0}'` | xargs -0 echo) \
    && sudo installer -pkg "${MOUNTDIR}/Extras/FUSE for macOS 3.4.1.pkg" -target /
    sudo chown -R vagrant /usr/local  # brew must be able to create stuff here
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew update
    brew install openssl
    brew install lz4
    brew install xz  # required for python lzma module
    brew install fakeroot
    brew install git
    brew install pkg-config
    touch ~vagrant/.bash_profile ; chown vagrant ~vagrant/.bash_profile
  EOF
end

def packages_freebsd
  return <<-EOF
    # install all the (security and other) updates, base system
    freebsd-update --not-running-from-cron fetch install
    # for building borgbackup and dependencies:
    pkg install -y openssl liblz4 fusefs-libs pkgconf
    pkg install -y fakeroot git bash
    # for building python:
    pkg install -y sqlite3
    # filesystem drivers
    pkg install -y openssh sshfs samba ntfs-3g
    # make bash default / work:
    chsh -s bash vagrant
    mount -t fdescfs fdesc /dev/fd
    echo 'fdesc	/dev/fd		fdescfs		rw	0	0' >> /etc/fstab
    # make FUSE work
    echo 'fuse_load="YES"' >> /boot/loader.conf
    echo 'vfs.usermount=1' >> /etc/sysctl.conf
    kldload fuse
    sysctl vfs.usermount=1
    pw groupmod operator -M vagrant
    touch ~vagrant/.bash_profile ; chown vagrant ~vagrant/.bash_profile
    # install all the (security and other) updates, packages
    pkg update
    yes | pkg upgrade
  EOF
end

def packages_openbsd
  return <<-EOF
    . ~/.profile
    mkdir -p /home/vagrant/borg
    rsync -aH /vagrant/borg/ /home/vagrant/borg/
    rm -rf /vagrant/borg
    ln -sf /home/vagrant/borg /vagrant/
    pkg_add bash
    chsh -s /usr/local/bin/bash vagrant
    pkg_add openssl
    pkg_add lz4
    # pkg_add fuse  # does not install, sdl dependency missing
    pkg_add git  # no fakeroot
    pkg_add py3-setuptools
    ln -sf /usr/local/bin/python3.4 /usr/local/bin/python3
    ln -sf /usr/local/bin/python3.4 /usr/local/bin/python
    easy_install-3.4 pip
    pip3 install virtualenv
    touch ~vagrant/.bash_profile ; chown vagrant ~vagrant/.bash_profile
  EOF
end

def packages_netbsd
  return <<-EOF
    hostname netbsd  # the box we use has an invalid hostname
    PKG_PATH="ftp://ftp.NetBSD.org/pub/pkgsrc/packages/NetBSD/amd64/6.1.5/All/"
    export PKG_PATH
    pkg_add mozilla-rootcerts lz4 git bash
    chsh -s bash vagrant
    mkdir -p /usr/local/opt/lz4/include
    mkdir -p /usr/local/opt/lz4/lib
    ln -s /usr/pkg/include/lz4*.h /usr/local/opt/lz4/include/
    ln -s /usr/pkg/lib/liblz4* /usr/local/opt/lz4/lib/
    touch /etc/openssl/openssl.cnf  # avoids a flood of "can't open ..."
    mozilla-rootcerts install
    pkg_add pkg-config  # avoids some "pkg-config missing" error msg, even without fuse
    # pkg_add fuse  # llfuse supports netbsd, but is still buggy.
    # https://bitbucket.org/nikratio/python-llfuse/issues/70/perfuse_open-setsockopt-no-buffer-space
    pkg_add samba
    pkg_add python34 py34-setuptools
    ln -s /usr/pkg/bin/python3.4 /usr/pkg/bin/python
    ln -s /usr/pkg/bin/python3.4 /usr/pkg/bin/python3
    easy_install-3.4 pip
    pip install virtualenv
    touch ~vagrant/.bash_profile ; chown vagrant ~vagrant/.bash_profile
  EOF
end

def install_pyenv(boxname)
  return <<-EOF
    curl -s -L https://raw.githubusercontent.com/yyuu/pyenv-installer/master/bin/pyenv-installer | bash
    echo 'export PATH="$HOME/.pyenv/bin:/vagrant/borg:$PATH"' >> ~/.bash_profile
    echo 'eval "$(pyenv init -)"' >> ~/.bash_profile
    echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bash_profile
    echo 'export PYTHON_CONFIGURE_OPTS="--enable-shared"' >> ~/.bash_profile
    echo 'export LANG=en_US.UTF-8' >> ~/.bash_profile
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
    pyenv install 3.4.0  # tests
    pyenv install 3.5.0  # tests
    pyenv install 3.5.2  # binary build, use latest 3.5.x release
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
    # use the latest 3.5 release
    pyenv global 3.5.2
    pyenv virtualenv 3.5.2 borg-env
    ln -s ~/.pyenv/versions/borg-env .
  EOF
end

def install_borg(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    pip install -U wheel  # upgrade wheel, too old for 3.5
    cd borg
    # clean up (wrong/outdated) stuff we likely got via rsync:
    rm -f borg/*.so borg/*.cpy*
    rm -f borg/{chunker,crypto,compress,hashindex,platform_linux}.c
    rm -rf borg/__pycache__ borg/support/__pycache__ borg/testsuite/__pycache__
    pip install -r requirements.d/development.txt
    # by using [fuse], setup.py can handle different fuse requirements:
    pip install -e .[fuse]
  EOF
end

def install_borg_no_fuse(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    pip install -U wheel  # upgrade wheel, too old for 3.5
    cd borg
    # clean up (wrong/outdated) stuff we likely got via rsync:
    rm -f borg/*.so borg/*.cpy*
    rm -f borg/{chunker,crypto,compress,hashindex,platform_linux}.c
    rm -rf borg/__pycache__ borg/support/__pycache__ borg/testsuite/__pycache__
    pip install -r requirements.d/development.txt
    pip install -e .
  EOF
end

def install_pyinstaller(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    git clone https://github.com/pyinstaller/pyinstaller.git
    cd pyinstaller
    # develop branch, with rebuilt bootloaders, with ThomasWaldmann/do-not-overwrite-LD_LP
    git checkout fd3df7796afa367e511c881dac983cad0697b9a3
    pip install -e .
  EOF
end

def install_pyinstaller_bootloader(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    git clone https://github.com/pyinstaller/pyinstaller.git
    cd pyinstaller
    # develop branch, with rebuilt bootloaders, with ThomasWaldmann/do-not-overwrite-LD_LP
    git checkout fd3df7796afa367e511c881dac983cad0697b9a3
    # build bootloader, if it is not included
    cd bootloader
    python ./waf all
    cd ..
    pip install -e .
  EOF
end

def build_binary_with_pyinstaller(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    cd borg
    pyinstaller -F -n borg.exe --distpath=/vagrant/borg --clean src/borg/__main__.py --hidden-import=borg.platform.posix
  EOF
end

def run_tests(boxname)
  return "source /vagrant/borg/borg/vagrant-tools/run-tests.sh"
end

def fix_perms
  return <<-EOF
    # . ~/.profile

    if id "vagrant" >/dev/null 2>&1; then
      chown -R vagrant /vagrant/borg
    else
      chown -R ubuntu /vagrant/borg
    fi

  EOF
end

Vagrant.configure(2) do |config|
  # use rsync to copy content to the folder
  config.vm.synced_folder ".", "/vagrant/borg/borg", :type => "rsync", :rsync__args => ["--verbose", "--archive", "--delete", "-z"]
  # do not let the VM access . on the host machine via the default shared folder!
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # fix permissions on synced folder
  config.vm.provision "fix perms",                  :type => :shell, :privileged => true,  :inline => fix_perms

  config.vm.provider :virtualbox do |v|
    #v.gui = true
    v.cpus = 1
  end

  # Linux
  config.vm.define "centos7_64" do |b|
    b.vm.box = "centos/7"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "install system packages",       :type => :shell, :privileged => true, :inline => packages_redhatted
    b.vm.provision "install pyenv",                 :type => :shell, :privileged => true, :inline => install_pyenv("centos7_64")
    b.vm.provision "install pythons",               :type => :shell, :privileged => true, :inline => install_pythons("centos7_64")
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_pyenv_venv("centos7_64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg("centos7_64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("centos7_64")
  end

  config.vm.define "centos6_32" do |b|
    b.vm.box = "centos6-32"
    b.vm.provision "install system packages",       :type => :shell, :privileged => true, :inline => packages_redhatted
    b.vm.provision "install pyenv",                 :type => :shell, :privileged => true, :inline => install_pyenv("centos6_32")
    b.vm.provision "install pythons",               :type => :shell, :privileged => true, :inline => install_pythons("centos6_32")
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_pyenv_venv("centos6_32")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg_no_fuse("centos6_32")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("centos6_32")
  end

  config.vm.define "centos6_64" do |b|
    b.vm.box = "centos6-64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "install system packages",       :type => :shell, :privileged => true, :inline => packages_redhatted
    b.vm.provision "install pyenv",                 :type => :shell, :privileged => true, :inline => install_pyenv("centos6_64")
    b.vm.provision "install pythons",               :type => :shell, :privileged => true, :inline => install_pythons("centos6_64")
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_pyenv_venv("centos6_64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg_no_fuse("centos6_64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("centos6_64")
  end

  config.vm.define "xenial64" do |b|
    b.vm.box = "ubuntu/xenial64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages debianoid",            :type => :shell, :privileged => true, :inline => packages_debianoid
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_sys_venv("xenial64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg("xenial64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("xenial64")
  end

  config.vm.define "trusty64" do |b|
    b.vm.box = "ubuntu/trusty64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages debianoid",            :type => :shell, :privileged => true, :inline => packages_debianoid
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_sys_venv("trusty64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg("trusty64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("trusty64")
  end

  config.vm.define "jessie64" do |b|
    b.vm.box = "debian/jessie64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages debianoid",            :type => :shell, :privileged => true, :inline => packages_debianoid
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_sys_venv("jessie64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg("jessie64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("jessie64")
  end

  config.vm.define "wheezy32" do |b|
    b.vm.box = "boxcutter/debian79-i386"
    b.vm.provision "packages prepare wheezy",       :type => :shell, :privileged => true, :inline => packages_prepare_wheezy
    b.vm.provision "packages debianoid",            :type => :shell, :privileged => true, :inline => packages_debianoid
    b.vm.provision "install pyenv",                 :type => :shell, :privileged => true, :inline => install_pyenv("wheezy32")
    b.vm.provision "install pythons",               :type => :shell, :privileged => true, :inline => install_pythons("wheezy32")
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_pyenv_venv("wheezy32")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg("wheezy32")
    # XXX https://github.com/borgbackup/borg/issues/1506
    b.vm.provision "install pyinstaller",           :type => :shell, :privileged => true, :inline => install_pyinstaller("wheezy32")
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => true, :inline => build_binary_with_pyinstaller("wheezy32")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("wheezy32")
  end

  config.vm.define "wheezy64" do |b|
    b.vm.box = "boxcutter/debian79"
    b.vm.provision "packages prepare wheezy",       :type => :shell, :privileged => true, :inline => packages_prepare_wheezy
    b.vm.provision "packages debianoid",            :type => :shell, :privileged => true, :inline => packages_debianoid
    b.vm.provision "install pyenv",                 :type => :shell, :privileged => true, :inline => install_pyenv("wheezy64")
    b.vm.provision "install pythons",               :type => :shell, :privileged => true, :inline => install_pythons("wheezy64")
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_pyenv_venv("wheezy64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg("wheezy64")
    b.vm.provision "install pyinstaller",           :type => :shell, :privileged => true, :inline => install_pyinstaller("wheezy64")
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => true, :inline => build_binary_with_pyinstaller("wheezy64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("wheezy64")
  end

  # OS X
  config.vm.define "darwin64" do |b|
    b.vm.box = "jhcook/yosemite-clitools"
    b.vm.provision "packages darwin",               :type => :shell, :privileged => true, :inline => packages_darwin
    b.vm.provision "install pyenv",                 :type => :shell, :privileged => true, :inline => install_pyenv("darwin64")
    b.vm.provision "fix pyenv",                     :type => :shell, :privileged => true, :inline => fix_pyenv_darwin("darwin64")
    b.vm.provision "install pythons",               :type => :shell, :privileged => true, :inline => install_pythons("darwin64")
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_pyenv_venv("darwin64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg("darwin64")
    b.vm.provision "install pyinstaller",           :type => :shell, :privileged => true, :inline => install_pyinstaller("darwin64")
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => true, :inline => build_binary_with_pyinstaller("darwin64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("darwin64")
  end

  # BSD
  config.vm.define "freebsd64" do |b|
    b.vm.box = "geoffgarside/freebsd-10.2"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "install system packages",       :type => :shell, :privileged => true, :inline => packages_freebsd
    b.vm.provision "install pyenv",                 :type => :shell, :privileged => true, :inline => install_pyenv("freebsd")
    b.vm.provision "install pythons",               :type => :shell, :privileged => true, :inline => install_pythons("freebsd")
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_pyenv_venv("freebsd")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg("freebsd")
    b.vm.provision "install pyinstaller",           :type => :shell, :privileged => true, :inline => install_pyinstaller_bootloader("freebsd")
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => true, :inline => build_binary_with_pyinstaller("freebsd")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("freebsd")
  end

  config.vm.define "openbsd64" do |b|
    b.vm.box = "kaorimatz/openbsd-5.9-amd64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages openbsd",              :type => :shell, :privileged => true, :inline => packages_openbsd
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_sys_venv("openbsd64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg_no_fuse("openbsd64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("openbsd64")
  end

  config.vm.define "netbsd64" do |b|
    b.vm.box = "alex-skimlinks/netbsd-6.1.5-amd64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages netbsd",               :type => :shell, :privileged => true, :inline => packages_netbsd
    b.vm.provision "build env",                     :type => :shell, :privileged => true, :inline => build_sys_venv("netbsd64")
    b.vm.provision "install borg",                  :type => :shell, :privileged => true, :inline => install_borg_no_fuse("netbsd64")
    b.vm.provision "run tests",                     :type => :shell, :privileged => true, :inline => run_tests("netbsd64")
  end
end
