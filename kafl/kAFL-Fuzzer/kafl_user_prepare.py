#!/usr/bin/env python3
#
# Copyright (C) 2017-2020 Sergej Schumilo, Cornelius Aschermann
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Helper script to harness simple Linux userspace binaries for use within a kAFL guest VM.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import uuid
from shutil import copyfile, rmtree

import common.color
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC, OKGREEN, BOLD, OKBLUE, INFO_PREFIX, OKGREEN
from common.self_check import self_check

__author__ = 'sergej'

KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
KAFL_BANNER = KAFL_ROOT + "banner.txt"
KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

def copy_dependencies(config, target_executable, target_folder, ld_type, agent_folder):
    result_string = ""
    is_asan_build = False
    print("\n" + OKGREEN + INFO_PREFIX + "Gathering dependencies of " + target_executable + ENDC)
    cmd = "lddtree -l " + target_executable
    download_script = ""
    try:
        proc = subprocess.Popen(cmd.split(" "), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.wait() != 0:
            raise Exception(proc.stderr.read())

        dependencies = proc.stdout.read().rstrip().split("\n")

        library_name = []

        libasan_name = ""

        for i in range(len(dependencies)):
            if dependencies[i] == "libnyx.so":
                dependencies[i] = agent_folder + "libnyx.so"
             

        i = 1
        for d in dependencies[1:]:
            #print(d)
            #download_script += "./hget %s %s\n"%(os.path.basename(d), os.path.basename(d))
            copyfile(d, "%s/%s"%(target_folder, os.path.basename(d)))

    except Exception as e:
        print(FAIL + "Error while running lddtree: " + str(e) + ENDC)

    return download_script


def execute(cmd, cwd, print_output=True, print_cmd=False):
    if print_cmd:
        print(OKBLUE + "\t  " + "Executing: " + " ".join(cmd) + ENDC)

    proc = subprocess.Popen(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if print_output:
        while True:
            output = proc.stdout.readline()
            if output:
                print(output),
            else:
                break
        while True:
            output = proc.stderr.readline()
            if output:
                print(FAIL + output + ENDC),
            else:
                break
    if proc.wait() != 0:
        print(FAIL + "Error while executing " + " ".join(cmd) + ENDC)


def check_elf(file):
    proc = subprocess.Popen(("file " + file).split(" "), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = proc.stdout.readline()
    proc.wait()

    if not (not "ELF" in output and not "executable" in output and not "Intel" in output):
        if "32-bit" in output:
            return "32"
        elif "64-bit" in output:
            return "64"

    print(FAIL + ERROR_PREFIX + "File is not an Intel x86 / x86-64 executable..." + ENDC)
    return None


def check_memlimit(memlimit, mode32):
    if memlimit < 5:
        print(FAIL + ERROR_PREFIX + "Memlimit to low..." + ENDC)
        return False
    if memlimit >= 2048 and mode32:
        print(FAIL + ERROR_PREFIX + "Memlimit to high (x86 mode)..." + ENDC)
        return False
    return True


def checks(config):
    if not os.path.isdir(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace-nyx/"):
        print(FAIL + ERROR_PREFIX + "Wrong path to \"AGENTS-FOLDER\" configured..." + ENDC)
        return False
    return True


def compile(config):

    if config.argument_values["spec"]:
        SPEC_FOLDER = os.path.abspath(config.argument_values["spec"])
    else:
        SPEC_FOLDER = None

    AFL_MODE = config.argument_values["afl_mode"]
    DELAYED_INIT = config.argument_values["delayed_init"]
    FAST_EXIT_MODE = config.argument_values["fast_reload_mode"]
    LEGACY_FILE_MODE = config.argument_values["file"]
    LEGACY_MODE = config.argument_values["legacy"]

    if not LEGACY_MODE and not SPEC_FOLDER:
        print(FAIL + "Error: spec not found!" + ENDC)
        return 

    if len(os.listdir(config.argument_values["output_dir"])) != 0:
        if config.argument_values["purge"]:
            print(WARNING + "Warning: %s was not empty!"%(config.argument_values["output_dir"]) + ENDC)
            rmtree(config.argument_values["output_dir"])
            os.mkdir(config.argument_values["output_dir"])
        else:
            print(FAIL + "Error: %s is not empty!"%(config.argument_values["output_dir"]) + ENDC)
            return

    if not check_memlimit(config.argument_values["m"], config.argument_values["mode"] == "m32"):
        return False

    elf_mode = check_elf(config.argument_values["binary_file"])
    if not elf_mode:
        return False

    print(OKGREEN + INFO_PREFIX + "Executable architecture is Intel " + elf_mode + "-bit ..." + ENDC)
    if (elf_mode == "32" and config.argument_values["mode"] == "m64") or (
            elf_mode == "64" and config.argument_values["mode"] == "m32"):
        print(WARNING + WARNING_PREFIX + "Executable architecture mismatch!" + ENDC)
        return False

    if config.argument_values["mode"] == "m64":
        objcopy_type = "elf64-x86-64"
        mode = "64"
        ld_type = "elf_x86_64"
        agent_folder = config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace-nyx/bin64/"
        print(OKGREEN + INFO_PREFIX + "Recompiling..." + ENDC)

        if SPEC_FOLDER:
            os.environ["NYX_SPEC_FOLDER"] = SPEC_FOLDER
        if LEGACY_MODE:
            os.environ["LEGACY_MODE"] = "ON"

        execute(["bash", "compile_64.sh"], config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace-nyx/",
                    print_output=True)



        #execute("gcc -shared -O0 -m64 -Werror -fPIC src/ld_preload_fuzz.c -I../../  -ISPEC_FOLDER -o bin64/ld_preload_fuzz.so -ldl -Isrc".replace("SPEC_FOLDER", SPEC_FOLDER).split(" "), config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/", print_output=True)
        #execute("gcc -shared -O0 -m64 -Werror -fPIC src/ld_preload_fuzz.c -I../../  -I../../../smbc_example/build -o bin64/ld_preload_fuzz.so -ldl -Isrc".split(" "), config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/", print_output=True)

    else:
        objcopy_type = "elf32-i386"
        mode = "32"
        ld_type = "elf_i386"
        agent_folder = config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace-nyx/bin32/"
        execute(["bash", "compile_32.sh"], config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace-nyx/",
                    print_output=True)

    #download_script = "chmod +x hget\n"
    #download_script += "cp hget /tmp/\n"
    download_script = "cd /target/\n"

    download_script += "echo 0 > /proc/sys/kernel/randomize_va_space\n"

    #download_script += "./hget hcat hcat\n"
    #download_script += "./hget habort habort\n"
    download_script += "chmod +x hcat\n"
    download_script += "chmod +x habort\n"

    #download_script += "./hget ld_preload_fuzz.so ld_preload_fuzz.so\n"
    download_script += "chmod +x ld_preload_fuzz.so\n"


    download_script += "echo \"Let's get our dependencies...\" | ./hcat\n"
    download_script += copy_dependencies(config, config.argument_values["binary_file"],  config.argument_values["output_dir"], ld_type, agent_folder)

    #download_script += "echo \"Let's get our target executable...\" | ./hcat\n"
    copyfile(config.argument_values["binary_file"], "%s/%s"%(config.argument_values["output_dir"], os.path.basename(config.argument_values["binary_file"])))
    #download_script += "./hget %s target_executable\n"%(os.path.basename(config.argument_values["binary_file"]))
    download_script += "ln %s target_executable\n" % os.path.basename(config.argument_values["binary_file"])
    download_script += "chmod +x %s\n" % os.path.basename(config.argument_values["binary_file"])

    hcat_file = agent_folder + "hcat"
    hget_file = agent_folder + "hget"
    habort_file = agent_folder + "habort"

    copyfile(hcat_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(hcat_file)))
    copyfile(hget_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(hget_file)))
    copyfile(habort_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(habort_file)))

    if LEGACY_MODE:
        ld_preload_fuzz_file = agent_folder + "ld_preload_fuzz.so"
        ld_preload_fuzz_file_legacy = agent_folder + "ld_preload_fuzz_legacy.so"
        copyfile(ld_preload_fuzz_file_legacy, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(ld_preload_fuzz_file)))
    else:
        ld_preload_fuzz_file = agent_folder + "ld_preload_fuzz.so"
        copyfile(ld_preload_fuzz_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(ld_preload_fuzz_file)))

    if (config.argument_values["extra_file"]):
        copyfile(config.argument_values["extra_file"], "%s/%s"%(config.argument_values["output_dir"],os.path.basename(config.argument_values["extra_file"])))
        #download_script += "./hget \"%s\" \"%s\"\n"%(os.path.basename(config.argument_values["extra_file"]), os.path.basename(config.argument_values["extra_file"]))


    download_script += "LD_LIBRARY_PATH=/target/ "
    download_script += "LD_BIND_NOW=1 LD_PRELOAD=/target/ld_preload_fuzz.so "
    download_script += "ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:exitcode=101 "

    if DELAYED_INIT:
        download_script += "DELAYED_NYX_FUZZER_INIT=ON "
    if AFL_MODE:
        download_script += "NYX_AFL_PLUS_PLUS_MODE=ON "
    if FAST_EXIT_MODE:
        download_script += "NYX_FAST_EXIT_MODE=ON "
    if LEGACY_FILE_MODE:
        download_script += "NYX_LEGACY_FILE_MODE=%s"%(config.argument_values["file"])

    download_script += " ./target_executable %s\n"%(config.argument_values["args"]) # fixme

 
    download_script += "dmesg | grep segfault | ./hcat\n"
    download_script += "./habort\n"

    # Todo: ASAN, memlimit, stdin, filemode ...

    f = open("%s/fuzz.sh"%(config.argument_values["output_dir"]), "w")
    f.write(download_script)
    f.close()

    return True

def main():

    print("<< " + BOLD + OKGREEN + sys.argv[0] +
            ": kAFL Binary Packer for Userspace Fuzzing " + ENDC + ">>\n")

    if not self_check(KAFL_ROOT):
        sys.exit(os.EX_SOFTWARE)

    from common.config import UserPrepareConfiguration
    try:
        config = UserPrepareConfiguration(KAFL_CONFIG)
    except:
        raise
        sys.exit(os.EX_USAGE)

    if not checks(config):
        raise
        sys.exit(os.EX_USAGE)

    if not compile(config):
        raise
        sys.exit(os.EX_USAGE)


if __name__ == "__main__":
    try:
        main()
    except:
        raise
        sys.exit(os.EX_SOFTWARE)
