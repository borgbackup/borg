# -*- mode: ruby -*-
# vi: set ft=ruby :

# TODO
# add pkg-config to sphinx docs, needed for fuse
# reduce lzma compression level to << 9 in unit tests, needs more memory than vagrant box has
# /usr/local/include/lz4.h for freebsd - use same code as for finding the openssl headers
# llfuse <0.41 >0.41.1 broken install due to UnicodeError

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
    apt-get install -y python3-dev python3-setuptools
    apt-get install -y libssl-dev libacl1-dev liblz4-dev
    apt-get install -y libfuse-dev fuse pkg-config
    apt-get install -y fakeroot build-essential git
    apt-get install -y curl
    # this way it works on older dists (like ubuntu 12.04) also:
    easy_install3 pip
    pip3 install virtualenv
  EOF
end

def packages_freebsd
  return <<-EOF
    pkg install -y python34 py34-setuptools34
    ln -s /usr/local/bin/python3.4 /usr/local/bin/python3
    pkg install -y openssl liblz4
    pkg install -y fusefs-libs pkgconf
    pkg install -y fakeroot git
    pkg install -y curl
    easy_install-3.4 pip
    pip3 install virtualenv
    # make FUSE work
    echo 'fuse_load="YES"' >> /boot/loader.conf
    echo 'vfs.usermount=1' >> /etc/sysctl.conf
    kldload fuse
    sysctl vfs.usermount=1
    pw groupmod operator -M vagrant
  EOF
end

def packages_darwin
  return <<-EOF
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew update || brew update
    brew outdated openssl || brew upgrade openssl
    brew outdated pyenv || brew upgrade pyenv
    brew install lz4
    brew install osxfuse
    pyenv install 3.4.3
    pyenv global 3.4.3
    pyenv rehash
    python -m pip install --user virtualenv
  EOF
end

def prepare_user(boxname)
  return <<-EOF
    echo export 'PATH=/usr/local/bin:$PATH' >> ~/.profile
    . ~/.profile

    cd /vagrant/borg
    virtualenv --python=python3 borg-env
    . borg-env/bin/activate

    cd borg
    pip install -U pip setuptools
    pip install 'llfuse<0.41'  # 0.41 does not install due to UnicodeDecodeError
    pip install -r requirements.d/development.txt
    pip install -e .

    echo
    echo "Run:"
    echo "  vagrant rsync #{boxname}"
    echo "  vagrant ssh #{boxname} -c 'cd project/path; ...'"
  EOF
end

def fix_perms
  return <<-EOF
    chown -R vagrant /vagrant/borg
  EOF
end

Vagrant.configure(2) do |config|
  # use rsync to copy content to the folder
  config.vm.synced_folder ".", "/vagrant/borg/borg", :type => "rsync"
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # fix permissions on synced folder
  config.vm.provision "fix perms", :type => :shell, :inline => fix_perms

  config.vm.define "trusty64" do |b|
    b.vm.box = "ubuntu/trusty64"
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid
    b.vm.provision "prepare user", :type => :shell, :privileged => false, :inline => prepare_user("trusty64")
  end

  config.vm.define "precise32" do |b|
    b.vm.box = "ubuntu/precise32"
    b.vm.provision "packages prepare precise", :type => :shell, :inline => packages_prepare_precise
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid
    b.vm.provision "prepare user", :type => :shell, :privileged => false, :inline => prepare_user("precise32")
  end

  config.vm.define "jessie64" do |b|
    b.vm.box = "debian/jessie64"
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid
    b.vm.provision "prepare user", :type => :shell, :privileged => false, :inline => prepare_user("jessie64")
  end

  config.vm.define "wheezy32" do |b|
    b.vm.box = "puppetlabs/debian-7.8-32-nocm"
    b.vm.provision "packages prepare wheezy", :type => :shell, :inline => packages_prepare_wheezy
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid
    b.vm.provision "prepare user", :type => :shell, :privileged => false, :inline => prepare_user("wheezy32")
  end

  # BSD
  config.vm.define "freebsd" do |b|
    b.vm.box = "geoffgarside/freebsd-10.2"
    #b.vm.base_mac = "11:22:33:44:56:67"
    b.vm.provision "packages freebsd", :type => :shell, :inline => packages_freebsd
    b.vm.provision "prepare user", :type => :shell, :privileged => false, :inline => prepare_user("freebsd")
  end

  # OS X
  config.vm.define "darwin" do |b|
    b.vm.box = "jhcook/yosemite-clitools"
    b.vm.provision "packages darwin", :type => :shell, :privileged => false, :inline => packages_darwin
    b.vm.provision "prepare user",   :type => :shell, :privileged => false, :inline => prepare_user("darwin")
  end
end
