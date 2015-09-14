# -*- mode: ruby -*-
# vi: set ft=ruby :

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

def packages_centos
  return <<-EOF
    yum install -y epel-release
    yum update -y
    yum install -y python34 python34-devel
    ln -s /usr/bin/python3.4 /usr/bin/python3
    yum install -y openssl-devel openssl
    yum install -y libacl-devel libacl
    yum install -y lz4-devel
    yum install -y fuse-devel fuse pkgconfig
    yum install -y fakeroot gcc git
    yum install -y python-pip
    pip install virtualenv
  EOF
end

def packages_debianoid
  return <<-EOF
    apt-get update
    apt-get install -y python3-dev python3-setuptools
    apt-get install -y libssl-dev libacl1-dev liblz4-dev
    apt-get install -y libfuse-dev fuse pkg-config
    apt-get install -y fakeroot build-essential git
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

def packages_openbsd
  return <<-EOF
    . ~/.profile
    mkdir -p /home/vagrant/borg
    rsync -aH /vagrant/borg/ /home/vagrant/borg/
    rm -rf /vagrant/borg
    ln -sf /home/vagrant/borg /vagrant/
    pkg_add bash
    chsh -s /usr/local/bin/bash vagrant
    pkg_add python-3.4.2
    pkg_add py3-setuptools
    ln -sf /usr/local/bin/python3.4 /usr/local/bin/python3
    ln -sf /usr/local/bin/python3.4 /usr/local/bin/python
    pkg_add openssl
    pkg_add lz4
    # pkg_add fuse  # does not install, sdl dependency missing
    pkg_add git  # no fakeroot
    easy_install-3.4 pip
    pip3 install virtualenv
  EOF
end

def packages_darwin
  return <<-EOF
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew update
    # this installs osxfuse 2.8.0 (which is based on libfuse 2.7.3).
    # llfuse later complains about needing (libfuse) 2.8.0 at least.
    #brew install caskroom/cask/brew-cask
    #brew cask install osxfuse  # needs cask install because of apple's unsigned kext ban
    # get osxfuse 3.0.x pre-release code from github:
    curl https://github.com/osxfuse/osxfuse/releases/download/osxfuse-3.0.5/osxfuse-3.0.5.dmg -L >osxfuse.dmg
    MOUNTDIR=$(echo `hdiutil mount osxfuse.dmg | tail -1 | awk '{$1="" ; print $0}'` | xargs -0 echo) \
    && sudo installer -pkg "${MOUNTDIR}/Extras/FUSE for OS X 3.0.5.pkg" -target /
    brew install openssl
    brew install lz4
    # looks dirty, is there a better way without root?:
    mkdir -p /usr/local/opt/lz4
    ln -s /usr/local/Cellar/lz4/r*/include /usr/local/opt/lz4/
    ln -s /usr/local/Cellar/lz4/r*/lib /usr/local/opt/lz4/
    brew install fakeroot
    brew install pyenv
    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi
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

    # initialize python on darwin
    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi

    cd /vagrant/borg
    python -m virtualenv --python=python3 borg-env
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
  # do not let the VM access . on the host machine via the default shared folder!
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # fix permissions on synced folder
  config.vm.provision "fix perms", :type => :shell, :inline => fix_perms

  config.vm.provider :virtualbox do |v|
    #v.gui = true
    v.cpus = 2
  end

  config.vm.define "centos7" do |b|
    b.vm.box = "centos/7"
    b.vm.provision "packages centos7 64", :type => :shell, :inline => packages_centos
    b.vm.provision "prepare user", :type => :shell, :privileged => false, :inline => prepare_user("centos7_64")
  end

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
    b.vm.provision "packages freebsd", :type => :shell, :inline => packages_freebsd
    b.vm.provision "prepare user", :type => :shell, :privileged => false, :inline => prepare_user("freebsd")
  end

  config.vm.define "openbsd" do |b|
    b.vm.box = "bodgit/openbsd-5.7-amd64"
    b.vm.provision "packages openbsd", :type => :shell, :inline => packages_openbsd
    b.vm.provision "prepare user", :type => :shell, :privileged => false, :inline => prepare_user("openbsd")
  end

  # OS X
  config.vm.define "darwin" do |b|
    b.vm.box = "jhcook/yosemite-clitools"
    b.vm.provision "packages darwin", :type => :shell, :privileged => false, :inline => packages_darwin
    b.vm.provision "prepare user",   :type => :shell, :privileged => false, :inline => prepare_user("darwin")
  end
end
