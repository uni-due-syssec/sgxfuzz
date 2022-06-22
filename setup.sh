#!/usr/bin/env bash

set -e

# TODO: install packages
#  python2 python3 libpixman-1-dev pax-utils bc linux-headers
#  make cmake gcc g++ pkg-config unzip
#  python3-virtualenv python2-dev python3-dev
#  libglib2.0-dev

# Compile QEMU-Nyx
qemu_nyx() {
pushd QEMU-Nyx
sed -i "s/--enable-gtk//g" ./compile_qemu_nyx.sh
./compile_qemu_nyx.sh lto
popd
}

# Install KVM-Nyx binary release
kvm_nyx_binary() {
if [[ "$(uname -r)" != "5.10.75-051075-generic" ]]; then
	wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.10.75/amd64/linux-image-unsigned-5.10.75-051075-generic_5.10.75-051075.202110201038_amd64.deb \
		https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.10.75/amd64/linux-modules-5.10.75-051075-generic_5.10.75-051075.202110201038_amd64.deb \
		https://github.com/nyx-fuzz/KVM-Nyx/releases/download/v5.10.73-1.1/kvm-nyx-5.10.73-1.1.zip

	echo "Warning! Installing Kernel ... (Press Enter)" && read -r
	sudo dpkg -i linux-*5.10.75*.deb

	mkdir -p kvm-nyx-release
	unzip -u -d kvm-nyx-release kvm-nyx-5.10.73-1.1.zip

	submenu=$(grep -E submenu.*Advanced.*menuentry_id_option /boot/grub/grub.cfg | grep -oP "(?<=menuentry_id_option ')[^']+(?=')")
	menuentry=$(grep -E menuentry.*Ubuntu.*5.10.75-051075.*menuentry_id_option /boot/grub/grub.cfg | grep -iv recovery | grep -oP "(?<=menuentry_id_option ')[^']+(?=')")
	sudo grub-reboot "$submenu>$menuentry"

	sudo reboot
	exit 0
fi
}

# Compile KVM-Nyx
kvm_nyx_standalone() {
pushd KVM-Nyx
set +e
patch -Np0 -r - -F 0 <<'EOF'
--- compile_kvm_nyx_standalone.sh
+++ compile_kvm_nyx_standalone.sh
@@ -1,4 +1,4 @@
-yes | make oldconfig &&
+yes "" | make oldconfig &&
 make modules_prepare &&
 cp /lib/modules/`uname -r`/build/scripts/module.lds scripts/ &&
 cp /lib/modules/`uname -r`/build/Module.symvers . &&

--- tools/lib/subcmd/subcmd-util.h
+++ tools/lib/subcmd/subcmd-util.h
@@ -47,6 +47,8 @@ static NORETURN inline void die(const char *err, ...)
 		} \
 	} while(0)
 
+#pragma GCC diagnostic push
+#pragma GCC diagnostic ignored "-Wuse-after-free"
 static inline void *xrealloc(void *ptr, size_t size)
 {
 	void *ret = realloc(ptr, size);
@@ -61,6 +63,7 @@ static inline void *xrealloc(void *ptr, size_t size)
 	}
 	return ret;
 }
+#pragma GCC diagnostic pop
 
 #define astrcatf(out, fmt, ...)						\
 ({									\
EOF
set -e

sh compile_kvm_nyx_standalone.sh
popd
}

venvs() {
# Create venvs
if command -v virtualenv >& /dev/null; then
	VENV_CMD=virtualenv
elif python3 -m virtualenv -h >& /dev/null; then
	VENV_CMD="python3 -m virtualenv"
elif python -m virtualenv -h >& /dev/null; then
	VENV_CMD="python -m virtualenv"
else
	echo "Cannot create venvs"
	exit 1
fi

if [[ ! -d venv-python2 ]]; then
	$VENV_CMD -p python2 --always-copy venv-python2

	PY2=$(realpath venv-python2/bin/python2)

	if [[ -f /usr/share/python-wheels/pep517-0.9.1-py2.py3-none-any.whl ]]; then
		# Disable system-wide pep517
		# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=955414
		sudo chmod o+r /usr/share/python-wheels/pep517-0.9.1-py2.py3-none-any.whl
		$PY2 -m pip install -I wheel pep517
		sudo chmod o-r /usr/share/python-wheels/pep517-0.9.1-py2.py3-none-any.whl
	fi

	$PY2 -m pip install configparser mmh3 lz4 psutil ipdb msgpack inotify

	if [[ -f /usr/share/python-wheels/pep517-0.9.1-py2.py3-none-any.whl ]]; then
		sudo chmod o+r /usr/share/python-wheels/pep517-0.9.1-py2.py3-none-any.whl
	fi
fi

if [[ ! -d venv-python3 ]]; then
	$VENV_CMD -p python3 --always-copy venv-python3

	PY3=$(realpath venv-python3/bin/python3)

	$PY3 -m pip install six python-dateutil msgpack mmh3 lz4 psutil fastrand inotify pgrep
fi
}

zydis() {
	pushd zydis
	cmake .
	make -j
	sudo make install
}


# Install: cmake

# TODO: zydis, native-sgx-runner, QEMU-Nyx, KVM-Nyx

git submodule update --init --recursive --recommend-shallow --depth=1

# kvm_nyx_standalone
kvm_nyx_binary

qemu_nyx
venvs
zydis
