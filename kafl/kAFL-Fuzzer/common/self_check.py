# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import subprocess
import sys
from fcntl import ioctl

from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC


def check_if_nativ_lib_compiled(kafl_root):
    if not (os.path.exists(kafl_root + "fuzzer/native/") and
            os.path.exists(kafl_root + "fuzzer/native/bitmap.so")):
        print(WARNING + "Attempting to build missing file fuzzer/native/bitmap.so ..." + ENDC)

        p = subprocess.Popen(("make -C " + kafl_root + "fuzzer/native/").split(" "),
                             stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

        if p.wait() != 0:
            print(FAIL + ERROR_PREFIX + "Build failed, please check.." + ENDC)
            return False
    return True


def check_if_installed(cmd):
    p = subprocess.Popen(("which " + cmd).split(" "), stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    if p.wait() != 0:
        return False
    return True


def check_version():
    if sys.version_info < (3, 0, 0):
        print(FAIL + ERROR_PREFIX + "This script requires python 3!" + ENDC)
        return False
    return True


def check_packages():
    try:
        import msgpack
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'msgpack' is missing!" + ENDC)
        return False

    if msgpack.version < (0,6,0):
        print(FAIL + ERROR_PREFIX + "Package 'msgpack' is too old, try pip3 install -U msgpack!" + ENDC)
        return False

    try:
        import mmh3
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'mmh3' is missing!" + ENDC)
        return False

    try:
        import lz4
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'lz4' is missing!" + ENDC)
        return False

    try:
        import psutil
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'psutil' is missing!" + ENDC)
        return False

    if not check_if_installed("lddtree"):
        print(FAIL + ERROR_PREFIX + "Tool 'lddtree' is missing (Hint: run `sudo apt install pax-utils`)!" + ENDC)
        return False

    try:
        import fastrand
    except ImportError:
        print(
            FAIL + ERROR_PREFIX + "Package 'fastrand' is missing!" + ENDC)
        return False

    try:
        import inotify
    except ImportError:
        print(
            FAIL + ERROR_PREFIX + "Package 'inotify' is missing!" + ENDC)
        return False

    return True

def vmx_pt_get_addrn(verbose=True):
    from fcntl import ioctl

    KVMIO = 0xAE
    KVM_VMX_PT_GET_ADDRN = KVMIO << (8) | 0xe9

    try:
        fd = open("/dev/kvm", "wb")
    except:
        if verbose:
            print(FAIL + ERROR_PREFIX + "KVM-PT is not loaded!" + ENDC)
        return 0

    try:
        ret = ioctl(fd, KVM_VMX_PT_GET_ADDRN, 0)
    except IOError:
        if verbose:
            print(WARNING + WARNING_PREFIX + "Kernel does not support multi-range tracing!" + ENDC)
        ret = 1
    finally:
        fd.close()
    return ret

def vmx_pt_check_addrn(config):

    if config.argument_values["ip3"]:
        ip_ranges = 4
    elif config.argument_values["ip2"]:
        ip_ranges = 3
    elif config.argument_values["ip1"]:
        ip_ranges = 2
    elif config.argument_values["ip0"]:
        ip_ranges = 1
    else:
        ip_ranges = 0

    ret = vmx_pt_get_addrn()

    if ip_ranges > ret:
        print(FAIL + ERROR_PREFIX + "CPU supports only " + str(ret) + " hardware ip trace filters!" + ENDC)
        return False
    return True

def check_vmx_pt():
    from fcntl import ioctl

    KVMIO = 0xAE
    KVM_VMX_PT_SUPPORTED = KVMIO << (8) | 0xe4

    try:
        fd = open("/dev/kvm", "wb")
    except:
        print(FAIL + ERROR_PREFIX + "Unable to access /dev/kvm. Check permissions and ensure dell.ko is loaded." + ENDC)
        return False

    try:
        ret = ioctl(fd, KVM_VMX_PT_SUPPORTED, 0)
    except IOError:
        print(FAIL + ERROR_PREFIX + "KVM-Nyx is not loaded!" + ENDC)
        return False
    fd.close()

    if ret == 0:
        print(FAIL + ERROR_PREFIX + "Intel PT is not supported on this CPU!" + ENDC)
        return False

    return True


def check_apple_osk(config):
    if config.argument_values["macOS"]:
        if config.config_values["APPLE-SMC-OSK"] == "":
            print(FAIL + ERROR_PREFIX + "APPLE SMC OSK is missing in kafl.ini!" + ENDC)
            return False
    return True


def check_apple_ignore_msrs(config):
    if config.argument_values["macOS"]:
        try:
            f = open("/sys/module/dell/parameters/ignore_msrs")
            if not 'Y' in f.read(1):
                print(
                    FAIL + ERROR_PREFIX + "KVM-PT is not properly configured! Please execute the following command:" \
                         + ENDC + "\n\n\tsudo su\n\techo 1 > /sys/module/kvm/parameters/ignore_msrs\n")
                return False
            else:
                return True
        except:
            pass
        finally:
            f.close()
        print(FAIL + ERROR_PREFIX + "KVM-PT is not ready?!" + ENDC)
        return False
    return True


def check_kafl_ini(rootdir):
    configfile = rootdir + "kafl.ini"
    if not os.path.exists(configfile):
        print(WARNING + WARNING_PREFIX + "Could not find kafl.ini. Creating default config at " + configfile + ENDC)
        from common.config import FuzzerConfiguration
        FuzzerConfiguration(configfile,skip_args=True).create_initial_config()
        return False
    return True


def check_qemu_version(config):
    if not config.config_values["QEMU_KAFL_LOCATION"] or config.config_values["QEMU_KAFL_LOCATION"] == "":
        print(FAIL + ERROR_PREFIX + "QEMU_KAFL_LOCATION is not set in kafl.ini!" + ENDC)
        return False

    if not os.path.exists(config.config_values["QEMU_KAFL_LOCATION"]):
        print(FAIL + ERROR_PREFIX + "QEMU-Nyx executable does not exist..." + ENDC)
        return False

    output = ""
    try:
        proc = subprocess.Popen([config.config_values["QEMU_KAFL_LOCATION"], "-version"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output = str(proc.stdout.readline())
        proc.wait()
    except:
        print(FAIL + ERROR_PREFIX + "Binary is not executable...?" + ENDC)
        return False
    if not ("QEMU-PT" in output and "(kAFL)" in output):
        print(FAIL + ERROR_PREFIX + "Wrong QEMU-PT executable..." + ENDC)
        return False
    return True

def check_radamsa_location(config):
    if "radamsa" not in config.argument_values or not config.argument_values["radamsa"]:
        return True

    if not config.config_values["RADAMSA_LOCATION"] or config.config_values["RADAMSA_LOCATION"] == "":
        print(FAIL + ERROR_PREFIX + "RADAMSA_LOCATION is not set in kafl.ini!" + ENDC)
        return False

    if not os.path.exists(config.config_values["RADAMSA_LOCATION"]):
        print(FAIL + ERROR_PREFIX + "RADAMSA executable does not exist. Try ./install.sh radamsa" + ENDC)
        return False

    return True

def check_cpu_num(config):
    import multiprocessing

    if 'p' not in config.argument_values:
        return True

    if int(config.argument_values["p"]) > int(multiprocessing.cpu_count()):
        print(FAIL + ERROR_PREFIX +
                "Only %d fuzzing processes are supported..." % (int(multiprocessing.cpu_count())) + ENDC)
        return False
    return True

def self_check(rootdir):
    if not check_if_nativ_lib_compiled(rootdir):
        return False
    if not check_kafl_ini(rootdir):
        return False
    if not check_version():
        return False
    if not check_packages():
        return False
    if not check_vmx_pt():
        return False
    return True


def post_self_check(config):
    if not check_apple_ignore_msrs(config):
        return False
    if not check_apple_osk(config):
        return False
    if not check_qemu_version(config):
        return False
    if not check_radamsa_location(config):
        return False
    if not vmx_pt_check_addrn(config):
        return False
    if not check_cpu_num(config):
        return False
    return True
