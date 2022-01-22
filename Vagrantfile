# -*- mode: ruby -*-
# vi: set ft=ruby :

# Automated creation of testing environments / binaries on misc. platforms

$cpus = Integer(ENV.fetch('VMCPUS', '4'))  # create VMs with that many cpus
$xdistn = Integer(ENV.fetch('XDISTN', '4'))  # dispatch tests to that many pytest workers
$wmem = $xdistn * 256  # give the VM additional memory for workers [MB]

def packages_debianoid(user)
  return <<-EOF
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # in case we get a grub update, it must not interactively ask for boot device:
    echo "set grub-pc/install_devices /dev/sda" | debconf-communicate
    # install all the (security and other) updates
    apt-get dist-upgrade -y
    # for building borgbackup and dependencies:
    apt-get install -y libssl-dev libacl1-dev liblz4-dev libfuse-dev fuse pkg-config
    usermod -a -G fuse #{user}
    chgrp fuse /dev/fuse
    chmod 666 /dev/fuse
    apt-get install -y fakeroot build-essential git curl
    apt-get install -y python3-dev python3-setuptools
    # for building python:
    apt-get install -y zlib1g-dev libbz2-dev libncurses5-dev libreadline-dev liblzma-dev libsqlite3-dev libffi-dev
    apt-get install -y python3-pip virtualenv python3-virtualenv
  EOF
end

def packages_redhatted
  return <<-EOF
    yum install -y epel-release
    yum update -y
    # for building borgbackup and dependencies:
    yum install -y openssl-devel openssl libacl-devel libacl lz4-devel fuse-devel fuse pkgconfig
    usermod -a -G fuse vagrant
    chgrp fuse /dev/fuse
    chmod 666 /dev/fuse
    yum install -y fakeroot gcc git patch
    # needed to compile msgpack-python (otherwise it will use slow fallback code):
    yum install -y gcc-c++
    # for building python:
    yum install -y zlib-devel bzip2-devel ncurses-devel readline-devel xz xz-devel sqlite-devel libffi-devel
    #yum install -y python-pip
    #pip install virtualenv
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
    brew install pkg-config readline openssl@1.1 zstd lz4 xz fakeroot git
    brew install --cask osxfuse
    brew upgrade  # upgrade everything
    echo 'export PKG_CONFIG_PATH=/usr/local/opt/openssl@1.1/lib/pkgconfig' >> ~vagrant/.bash_profile
  EOF
end

def packages_freebsd
  return <<-EOF
    # VM has no hostname set
    hostname freebsd
    # install all the (security and other) updates, base system
    freebsd-update --not-running-from-cron fetch install
    # for building borgbackup and dependencies:
    pkg install -y openssl liblz4 fusefs-libs pkgconf
    pkg install -y git bash
    # for building python:
    pkg install -y sqlite3 libffi
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
    # /dev/fuse has group operator
    chmod 666 /dev/fuse
    # install all the (security and other) updates, packages
    pkg update
    yes | pkg upgrade
  EOF
end

def packages_openbsd
  return <<-EOF
    pkg_add bash
    chsh -s /usr/local/bin/bash vagrant
    pkg_add lz4
    pkg_add zstd
    pkg_add git  # no fakeroot
    pkg_add py3-pip
    pkg_add py3-virtualenv
    ln -sf /usr/local/bin/virtualenv-3 /usr/local/bin/virtualenv
  EOF
end

def packages_netbsd
  return <<-EOF
    # use the latest stuff, some packages in "9.2" are quite broken
    echo 'http://ftp.NetBSD.org/pub/pkgsrc/packages/NetBSD/$arch/9.0_current/All' > /usr/pkg/etc/pkgin/repositories.conf
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
    ln -s /usr/pkg/lib/python3.8/_sysconfigdata_netbsd9.py /usr/pkg/lib/python3.8/_sysconfigdata__netbsd9_.py  # bug in netbsd 9.2, expected filename not there.
    pkg_add python39 py39-sqlite3 py39-pip py39-virtualenv py39-expat
    ln -s /usr/pkg/bin/python3.9 /usr/pkg/bin/python
    ln -s /usr/pkg/bin/python3.9 /usr/pkg/bin/python3
    ln -s /usr/pkg/bin/pip3.9 /usr/pkg/bin/pip
    ln -s /usr/pkg/bin/pip3.9 /usr/pkg/bin/pip3
    ln -s /usr/pkg/bin/virtualenv-3.9 /usr/pkg/bin/virtualenv
    ln -s /usr/pkg/bin/virtualenv-3.9 /usr/pkg/bin/virtualenv3
    ln -s /usr/pkg/lib/python3.9/_sysconfigdata_netbsd9.py /usr/pkg/lib/python3.9/_sysconfigdata__netbsd9_.py  # bug in netbsd 9.2, expected filename not there.
  EOF
end

def packages_openindiana
  return <<-EOF
    # needs separate provisioning step + reboot:
    #pkg update
    # already installed:
    #pkg install python-37 python-35 virtualenv-35 pip-35 clang-40 lz4 zstd git
    pkg install gcc-7
    ln -sf /usr/bin/python3.5 /usr/bin/pyton3
    ln -sf /usr/bin/virtualenv-3.5 /usr/bin/virtualenv
    ln -sf /usr/bin/pip-3.5 /usr/bin/pip
  EOF
end

# Install required cygwin packages and configure environment
#
# Microsoft/EdgeOnWindows10 image has MLS-OpenSSH installed by default,
# which is based on cygwin x86_64 but should not be used together with cygwin.
# In order to have have cygwin compatible bash 'ImagePath' is replaced with
# cygrunsrv of newly installed cygwin
#
# supported cygwin versions:
#   x86_64
#   x86
def packages_cygwin(version)
  setup_exe = "setup-#{version}.exe"

  return <<-EOF
    mkdir -p /cygdrive/c/cygwin
    powershell -Command '$client = new-object System.Net.WebClient; $client.DownloadFile("https://www.cygwin.com/#{setup_exe}","C:\\cygwin\\#{setup_exe}")'
    echo '
    REM --- Change to use different CygWin platform and final install path
    set CYGSETUP=#{setup_exe}
    REM --- Install build version of CygWin in a subfolder
    set OURPATH=%cd%
    set CYGBUILD="C:\\cygwin\\CygWin"
    set CYGMIRROR=http://mirrors.kernel.org/sourceware/cygwin/
    set BASEPKGS=openssh,rsync
    set BUILDPKGS=python3,python3-setuptools,python-devel,binutils,gcc-g++,libopenssl,openssl-devel,git,make,liblz4-devel,liblz4_1,curl
    %CYGSETUP% -q -B -o -n -R %CYGBUILD% -L -D -s %CYGMIRROR% -P %BASEPKGS%,%BUILDPKGS%
    cd /d C:\\cygwin\\CygWin\\bin
    regtool set /HKLM/SYSTEM/CurrentControlSet/Services/OpenSSHd/ImagePath "C:\\cygwin\\CygWin\\bin\\cygrunsrv.exe"
    bash -c "ssh-host-config --no"
    bash -c "chown sshd_server /cygdrive/c/cygwin/CygWin/var/empty"
    ' > /cygdrive/c/cygwin/install.bat

    echo "alias mkdir='mkdir -p'" > ~/.profile
    echo "export CYGWIN_ROOT=/cygdrive/c/cygwin/CygWin" >> ~/.profile
    echo 'export PATH=$CYGWIN_ROOT/bin:$PATH' >> ~/.profile

    echo '' > ~/.bash_profile

    cmd.exe /c 'setx /m PATH "C:\\cygwin\\CygWin\\bin;%PATH%"'
    source ~/.profile
    cd /cygdrive/c/cygwin && cmd.exe /c install.bat

    echo 'db_home: windows' > $CYGWIN_ROOT/etc/nsswitch.conf
  EOF
end

def install_cygwin_venv
  return <<-EOF
      python3 -m ensurepip -U --default-pip
      pip install virtualenv
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
    pyenv install 3.5.3  # tests, 3.5.3 is first to support openssl 1.1
    pyenv install 3.6.2  # tests
    pyenv install 3.7.11  # binary build, use latest 3.7.x release
    pyenv install 3.8.0  # tests
    pyenv install 3.9.0  # tests
    pyenv install 3.10.0  # tests
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
    # use the latest 3.7 release
    pyenv global 3.7.11
    pyenv virtualenv 3.7.11 borg-env
    ln -s ~/.pyenv/versions/borg-env .
  EOF
end

def install_borg(fuse)
  script = <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    pip install -U wheel  # upgrade wheel, too old for 3.5
    cd borg
    pip install -r requirements.d/development.lock.txt
    python setup.py clean
  EOF
  if fuse
    script += <<-EOF
      # by using [fuse], setup.py can handle different FUSE requirements:
      pip install -e .[fuse]
    EOF
  else
    script += <<-EOF
      pip install -e .
      # do not install llfuse into the virtualenvs built by tox:
      sed -i.bak '/fuse.txt/d' tox.ini
    EOF
  end
  return script
end

def install_pyinstaller()
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg
    . borg-env/bin/activate
    git clone https://github.com/thomaswaldmann/pyinstaller.git
    cd pyinstaller
    git checkout v4.2-maint
    python setup.py install
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

def run_tests(boxname)
  return <<-EOF
    . ~/.bash_profile
    cd /vagrant/borg/borg
    . ../borg-env/bin/activate
    if which pyenv 2> /dev/null; then
      # for testing, use the earliest point releases of the supported python versions.
      # on some dists, 3.10 does not compile, so if pyenv fails due to this, try without 3.10.
      pyenv global 3.5.3 3.6.2 3.7.11 3.8.0 3.9.0 3.10.0 || pyenv global 3.5.3 3.6.2 3.7.11 3.8.0 3.9.0
      pyenv local 3.5.3 3.6.2 3.7.11 3.8.0 3.9.0 3.10.0 || pyenv local 3.5.3 3.6.2 3.7.11 3.8.0 3.9.0
    fi
    # otherwise: just use the system python
    if which fakeroot 2> /dev/null; then
      echo "Running tox WITH fakeroot -u"
      fakeroot -u tox --skip-missing-interpreters -e py35,py36,py37,py38,py39,py310
    else
      echo "Running tox WITHOUT fakeroot -u"
      tox --skip-missing-interpreters -e py35,py36,py37,py38,py39,py310
    fi
  EOF
end

def fs_init(user)
  return <<-EOF
    # clean up (wrong/outdated) stuff we likely got via rsync:
    rm -rf /vagrant/borg/borg/.tox 2> /dev/null
    rm -rf /vagrant/borg/borg/borgbackup.egg-info 2> /dev/null
    rm -rf /vagrant/borg/borg/__pycache__ 2> /dev/null
    find /vagrant/borg/borg/src -name '__pycache__' -exec rm -rf {} \\;  2> /dev/null
    chown -R #{user} /vagrant/borg
    touch ~#{user}/.bash_profile ; chown #{user} ~#{user}/.bash_profile
    echo 'export LANG=en_US.UTF-8' >> ~#{user}/.bash_profile
    echo 'export LC_CTYPE=en_US.UTF-8' >> ~#{user}/.bash_profile
    echo 'export XDISTN=#{$xdistn}' >> ~#{user}/.bash_profile
  EOF
end

Vagrant.configure(2) do |config|
  # use rsync to copy content to the folder
  config.vm.synced_folder ".", "/vagrant/borg/borg", :type => "rsync", :rsync__args => ["--verbose", "--archive", "--delete", "-z"], :rsync__chown => false
  # do not let the VM access . on the host machine via the default shared folder!
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider :virtualbox do |v|
    #v.gui = true
    v.cpus = $cpus
  end

  # Linux
  config.vm.define "centos7_64" do |b|
    b.vm.box = "centos/7"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "install system packages", :type => :shell, :inline => packages_redhatted
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("centos7_64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("centos7_64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("centos7_64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(true)
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("centos7_64")
  end

  config.vm.define "focal64" do |b|
    b.vm.box = "ubuntu/focal64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("focal64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(true)
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("focal64")
  end

  config.vm.define "bionic64" do |b|
    b.vm.box = "ubuntu/bionic64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("bionic64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(true)
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("bionic64")
  end

  config.vm.define "buster64" do |b|
    b.vm.box = "debian/buster64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("buster64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(true)
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("buster64")
  end

  config.vm.define "stretch64" do |b|
    b.vm.box = "debian/stretch64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages debianoid", :type => :shell, :inline => packages_debianoid("vagrant")
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("stretch64")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("stretch64")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("stretch64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(true)
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("stretch64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("stretch64")
  end

  # OS X
  config.vm.define "darwin64" do |b|
    b.vm.box = "macos-sierra"
    b.vm.provider :virtualbox do |v|
      v.memory = 2048 + $wmem
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
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(true)
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("darwin64")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("darwin64")
  end

  # BSD
  config.vm.define "freebsd64" do |b|
    b.vm.box = "freebsd121-64"
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.ssh.shell = "sh"
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "install system packages", :type => :shell, :inline => packages_freebsd
    b.vm.provision "install pyenv", :type => :shell, :privileged => false, :inline => install_pyenv("freebsd")
    b.vm.provision "install pythons", :type => :shell, :privileged => false, :inline => install_pythons("freebsd")
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_pyenv_venv("freebsd")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(true)
    b.vm.provision "install pyinstaller", :type => :shell, :privileged => false, :inline => install_pyinstaller()
    b.vm.provision "build binary with pyinstaller", :type => :shell, :privileged => false, :inline => build_binary_with_pyinstaller("freebsd")
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("freebsd")
  end

  config.vm.define "openbsd64" do |b|
    b.vm.box = "openbsd64-64"  # note: basic openbsd install for vagrant WITH sudo and rsync pre-installed
    b.vm.provider :virtualbox do |v|
      v.memory = 1024 + $wmem
    end
    b.ssh.shell = "sh"
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages openbsd", :type => :shell, :inline => packages_openbsd
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("openbsd64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(false)
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("openbsd64")
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
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("netbsd64")
  end

  # rsync on openindiana has troubles, does not set correct owner for /vagrant/borg and thus gives lots of
  # permission errors. can be manually fixed in the VM by: sudo chown -R vagrant /vagrant/borg ; then rsync again.
  config.vm.define "openindiana64" do |b|
    b.vm.box = "openindiana"
    b.vm.provider :virtualbox do |v|
      v.memory = 3072 + $wmem
    end
    b.vm.provision "fs init", :type => :shell, :inline => fs_init("vagrant")
    b.vm.provision "packages openindiana", :type => :shell, :inline => packages_openindiana
    b.vm.provision "build env", :type => :shell, :privileged => false, :inline => build_sys_venv("openindiana64")
    b.vm.provision "install borg", :type => :shell, :privileged => false, :inline => install_borg(false)
    b.vm.provision "run tests", :type => :shell, :privileged => false, :inline => run_tests("openindiana64")
  end

  config.vm.define "windows10" do |b|
    b.vm.box = "Microsoft/EdgeOnWindows10"
    b.vm.guest = :windows
    b.vm.boot_timeout = 180
    b.vm.graceful_halt_timeout = 120

    b.ssh.shell = "sh -l"
    b.ssh.username = "IEUser"
    b.ssh.password = "Passw0rd!"
    b.ssh.insert_key = false

    b.vm.provider :virtualbox do |v|
      v.memory = 1536 + $wmem
      #v.gui = true
    end

    b.vm.provision "packages cygwin", :type => :shell, :privileged => false, :inline => packages_cygwin("x86_64")
    b.vm.provision :reload
    b.vm.provision "cygwin install pip", :type => :shell, :privileged => false, :inline => install_cygwin_venv
    b.vm.provision "cygwin build env", :type => :shell, :privileged => false, :inline => build_sys_venv("windows10")
    b.vm.provision "cygwin install borg", :type => :shell, :privileged => false, :inline => install_borg(false)
    b.vm.provision "cygwin run tests", :type => :shell, :privileged => false, :inline => run_tests("windows10")
  end
end
