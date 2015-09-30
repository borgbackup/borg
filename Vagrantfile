# -*- mode: ruby -*-
# vi: set ft=ruby :

# Automated creation of testing environment and standalones of borg-backup for various platforms.
#
# Usage:
#   To create and provision the VM:
#     vagrant up OS
#   To enter an ssh session in the VM:
#     vagrant ssh OS command
#   To shut down the VM:
#     vagrant halt OS
#   To shut down and destroy the VM:
#     vagrant destroy OS
#   To copy files from the VM (in this case, the pyinstaller-generated binaries)
#     rsync -av -e 'vagrant ssh OS' --  :~/vagrant/borg/borg/dist/borg ./

def packages_prepare_wheezy
  return <<-EOF
      # debian 7 wheezy does not have lz4, but it is available from wheezy-backports:
      echo "deb http://http.debian.net/debian wheezy-backports main" > /etc/apt/sources.list.d/wheezy-backports.list
  EOF
end

def packages_prepare_precise
  return <<-EOF
      # ubuntu 12.04 precise does not have lz4, but it is available from a ppa:
      add-apt-repository -y ppa:gezakovacs/lz4
  EOF
end

def packages_debianoid
  return <<-EOF
    apt-get update
    # for building borgbackup and dependencies:
    apt-get install -y libssl-dev libacl1-dev liblz4-dev libfuse-dev fuse pkg-config
    apt-get install -y fakeroot build-essential git
    apt-get install -y python3-dev python3-setuptools
    # this way it works on older dists (like ubuntu 12.04) also:
    easy_install3 pip
    pip3 install virtualenv
    touch ~vagrant/.bash_profile ; chown vagrant ~vagrant/.bash_profile
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
    # for building python:
    yum install -y zlib-devel bzip2-devel ncurses-devel readline-devel xz-devel sqlite-devel
    #yum install -y python-pip
    #pip install virtualenv
    touch ~vagrant/.bash_profile ; chown vagrant ~vagrant/.bash_profile
  EOF
end

def packages_darwin
  return <<-EOF
    # get osxfuse 3.0.x pre-release code from github:
    curl -s -L https://github.com/osxfuse/osxfuse/releases/download/osxfuse-3.0.5/osxfuse-3.0.5.dmg >osxfuse.dmg
    MOUNTDIR=$(echo `hdiutil mount osxfuse.dmg | tail -1 | awk '{$1="" ; print $0}'` | xargs -0 echo) \
    && sudo installer -pkg "${MOUNTDIR}/Extras/FUSE for OS X 3.0.5.pkg" -target /
    sudo chown -R vagrant /usr/local  # brew must be able to create stuff here
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew update
    brew install openssl
    brew install lz4
    brew install fakeroot
    brew install git
    touch ~vagrant/.bash_profile ; chown vagrant ~vagrant/.bash_profile
  EOF
end

def packages_freebsd
  return <<-EOF
    # for building borgbackup and dependencies:
    pkg install -y openssl liblz4 fusefs-libs pkgconf
    pkg install -y fakeroot git bash
    # for building python:
    pkg install sqlite3
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
    pkg_add python-3.4.2
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
    # llfuse does not support netbsd
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
    echo 'export PATH="$HOME/.pyenv/bin:$PATH"' >> ~/.bash_profile
    echo 'eval "$(pyenv init -)"' >> ~/.bash_profile
    echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bash_profile
    echo 'export PYTHON_CONFIGURE_OPTS="--enable-shared"' >> ~/.bash_profile
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
    pyenv install 3.2.2  # tests, 3.2(.0) and 3.2.1 deadlock, issue #221
    pyenv install 3.3.0  # tests
    pyenv install 3.4.0  # tests
    pyenv install 3.5.0  # tests
    #pyenv install 3.5.1  # binary build, use latest 3.5.x release
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
    pyenv global 3.5.0
    pyenv virtualenv 3.5.0 borg-env
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
    pip install 'llfuse<0.41'  # 0.41 does not install due to UnicodeDecodeError
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
    git checkout develop
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
    git checkout python3
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
    pyinstaller -F -n borg --hidden-import=logging.config borg/__main__.py
  EOF
end

def run_tests(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg/borg
    . ../borg-env/bin/activate
    if which pyenv > /dev/null; then
      # for testing, use the earliest point releases of the supported python versions:
      pyenv global 3.2.2 3.3.0 3.4.0 3.5.0
    fi
    # otherwise: just use the system python
    if which fakeroot > /dev/null; then
      fakeroot -u tox --skip-missing-interpreters
    else
      tox --skip-missing-interpreters
    fi
  EOF
end

def fix_perms
  return <<-EOF
    # . ~/.profile
    chown -R vagrant /vagrant/borg
  EOF
end

Vagrant.configure(2) do |config|
  # use rsync to copy content to the folder
  config.vm.synced_folder ".", "/vagrant/borg/borg", :type => "rsync"
  # do not let the VM access . on the host machine via the default shared folder!
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # fix permissions on synced folder
  config.vm.provision "fix perms", :type => :shell, :inline => fix_perms

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
    b.vm.provision "install system packages", :type => :shell, :inline => packages_redhatted
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("centos7_64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("centos7_64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("centos7_64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("centos7_64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("centos7_64")
  end

  config.vm.define "centos6_32" do |b|
    b.vm.box = "centos6-32"
    b.vm.provision "install system packages", :type => :shell, :inline => packages_redhatted
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("centos6_32")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("centos6_32")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("centos6_32")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("centos6_32")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller("centos6_32")
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("centos6_32")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("centos6_32")
  end

  config.vm.define "centos6_64" do |b|
    b.vm.box = "centos6-64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "install system packages", :type => :shell, :inline => packages_redhatted
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("centos6_64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("centos6_64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("centos6_64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("centos6_64")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller("centos6_64")
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("centos6_64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("centos6_64")
  end

  config.vm.define "trusty64" do |b|
    b.vm.box = "ubuntu/trusty64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("trusty64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("trusty64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("trusty64")
  end

  config.vm.define "precise32" do |b|
    b.vm.box = "ubuntu/precise32"
    b.vm.provision "packages prepare precise", :type => :shell, :inline => packages_prepare_precise
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("precise32")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("precise32")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("precise32")
  end

  config.vm.define "jessie64" do |b|
    b.vm.box = "debian/jessie64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("jessie64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("jessie64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("jessie64")
  end

  config.vm.define "wheezy32" do |b|
    b.vm.box = "puppetlabs/debian-7.8-32-nocm"
    b.vm.provision "packages prepare wheezy", :type => :shell, :inline => packages_prepare_wheezy
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("wheezy32")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("wheezy32")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("wheezy32")
  end

  # OS X
  config.vm.define "darwin64" do |b|
    b.vm.box = "jhcook/yosemite-clitools"
    b.vm.provision "packages darwin", :type => :shell, :privileged => false, :inline => packages_darwin
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("darwin64")
    b.vm.provision "fix pyenv", :type => :shell, :privileged => false, :inline => fix_pyenv_darwin("darwin64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("darwin64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("darwin64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("darwin64")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller("darwin64")
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("darwin64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("darwin64")
  end

  # BSD
  config.vm.define "freebsd64" do |b|
    b.vm.box = "geoffgarside/freebsd-10.2"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "install system packages", :type => :shell, :inline => packages_freebsd
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("freebsd")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("freebsd")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("freebsd")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("freebsd")
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller_bootloader("freebsd")
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("freebsd")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("freebsd")
  end

  config.vm.define "openbsd64" do |b|
    b.vm.box = "bodgit/openbsd-5.7-amd64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages openbsd", :type => :shell, :inline => packages_openbsd
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("openbsd64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("openbsd64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("openbsd64")
  end

  config.vm.define "netbsd64" do |b|
    b.vm.box = "alex-skimlinks/netbsd-6.1.5-amd64"
    b.vm.provider :virtualbox do |v|
      v.memory = 768
    end
    b.vm.provision "packages netbsd", :type => :shell, :inline => packages_netbsd
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("netbsd64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg("netbsd64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("netbsd64")
  end
end
