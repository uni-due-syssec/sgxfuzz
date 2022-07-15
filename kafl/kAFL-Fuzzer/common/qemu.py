# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Launch Qemu VMs and execute test inputs produced by kAFL-Fuzzer.
"""

import ctypes
import logging
import mmap
import os
import socket
import struct
import subprocess
import time
import sys
import shutil

from common.execution_result import ExecutionResult
from common.util import read_binary_file, atomic_write, strdump, print_hprintf
from common.log import FileFormatter
from fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from common.qemu_aux_buffer import QemuAuxBuffer
from common.qemu_aux_buffer import QemuAuxRC as RC

class QemuIOException(Exception):
        """Exception raised when Qemu interaction fails"""
        pass
class qemu:

    def __init__(self, qid, config, debug_mode=False, notifiers=True):

        self.debug_mode = debug_mode
        self.ijonmap_size = 0x1000 # quick fix - bitmaps are not processed!
        self.agent_size = config.config_values['AGENT_MAX_SIZE']
        self.bitmap_size = config.config_values['BITMAP_SHM_SIZE']
        self.payload_size = config.config_values['PAYLOAD_SHM_SIZE']
        self.prefix_limit = config.config_values['PAYLOAD_PREFIX_SHM_SIZE']
        self.payload_limit = config.config_values['PAYLOAD_SHM_SIZE'] - 5 - self.prefix_limit
        self.payload_prefix = b""
        self.ecall_id = None
        self.timeout_min = 1e-6  # minimum valid timeout/runtime = 1usec
        self.config = config
        self.qemu_id = str(qid)
        self.alt_bitmap = bytearray(self.bitmap_size)
        self.alt_edges = 0
        self.bb_seen = 0

        self.process = None
        self.control = None
        self.persistent_runs = 0

        project_name = self.config.argument_values['work_dir'].split("/")[-1]

        self.qemu_aux_buffer_filename = self.config.argument_values['work_dir'] + "/aux_buffer_" + self.qemu_id

        self.tracedump_filename = "/dev/shm/kafl_%s_pt_trace_dump_%s" % (project_name, self.qemu_id)

        self.binary_filename = self.config.argument_values['work_dir'] + "/program"
        self.bitmap_filename = self.config.argument_values['work_dir'] + "/bitmap_" + self.qemu_id
        self.ijonmap_filename = self.config.argument_values['work_dir'] + "/ijon_" + self.qemu_id
        self.payload_filename = self.config.argument_values['work_dir'] + "/payload_" + self.qemu_id
        self.control_filename = self.config.argument_values['work_dir'] + "/interface_" + self.qemu_id
        self.qemu_trace_log = self.config.argument_values['work_dir'] + "/qemu_trace_%s.log" % self.qemu_id
        self.qemu_serial_log = self.config.argument_values['work_dir'] + "/qemu_serial_%s.log" % self.qemu_id
        self.pipe_serial = not self.config.argument_values['no_pipe_serial']
        self.qemu_hprintf_log = self.config.argument_values['work_dir'] + "/qemu_hprintf_%s.log" % self.qemu_id
        self.pipe_hprintf = not self.config.argument_values['no_pipe_hprintf']

        self.hprintf_log =  True # FIXME self.config.log_hprintf or self.config.log_crashes
        self.hprintf_logfile = self.config.argument_values['work_dir'] + "/hprintf_%s.log" % self.qemu_id

        self.redqueen_workdir = RedqueenWorkdir(self.qemu_id, config)
        self.redqueen_workdir.init_dir()

        self.starved = False
        self.exiting = False

        self.cmd = self.config.config_values['QEMU_KAFL_LOCATION']

        if self.pipe_serial:
            self.cmd += " -serial file:" + self.qemu_serial_log

        # TODO: list append should work better than string concatenation, especially for str.replace() and later popen()
        self.cmd += " -enable-kvm" \
                    " -m " + str(config.argument_values['mem']) + \
                    " -net none" \
                    " -chardev socket,server,id=nyx_socket,path=" + self.control_filename + \
                    " -device nyx,chardev=nyx_socket" + \
                    ",workdir=" + self.config.argument_values['work_dir'] + \
                    ",worker_id=%s" % self.qemu_id + \
                    ",bitmap_size=" + str(self.bitmap_size) + \
                    ",input_buffer_size=" + str(self.payload_size)

        if self.config.argument_values['dump_pt']:
            self.cmd += ",dump_pt_trace"

        if self.debug_mode:
            self.cmd += ",debug_mode"

        if self.config.argument_values['sharedir']:
            self.cmd += ",sharedir=" + self.config.argument_values['sharedir']

        if not notifiers:
            self.cmd += ",crash_notifier=False"

        # if self.config.argument_values['R']:
        #    self.cmd += ",reload_mode=False"

        # qemu snapshots only work in VM mode (disk+ram image)
        # if self.config.argument_values['kernel'] or self.config.argument_values['bios']:
        #    self.cmd += ",disable_snapshot=True"

        for i in range(1):
            key = "ip" + str(i)
            if key in self.config.argument_values and self.config.argument_values[key]:
                range_a = hex(self.config.argument_values[key][0]).replace("L", "")
                range_b = hex(self.config.argument_values[key][1]).replace("L", "")
                self.cmd += ",ip" + str(i) + "_a=" + range_a + ",ip" + str(i) + "_b=" + range_b
                # self.cmd += ",filter" + str(i) + "=/dev/shm/kafl_filter" + str(i)

        if self.debug_mode:
            self.cmd += " -d kafl -D " + self.qemu_trace_log

        self.cmd += " -no-reboot"

        if self.config.argument_values['gdbserver']:
            # self.cmd += " -trace events=/tmp/events"
            self.cmd += " -s -S"

        if self.config.argument_values['X']:
            if qid == 0 or qid == 1337:
                self.cmd += " -display %s" % self.config.argument_values['X']
        else:
            self.cmd += " -display none"

        if self.config.argument_values['extra']:
            self.cmd += " " + self.config.argument_values['extra']

        # Lauch either as VM snapshot, direct kernel/initrd boot, or -bios boot
        if self.config.argument_values['vm_image']:
            self.cmd += " -drive " + self.config.argument_values['vm_image']
        elif self.config.argument_values['kernel']:
            self.cmd += " -kernel " + self.config.argument_values['kernel']
            if self.config.argument_values['initrd']:
                self.cmd += " -initrd " + self.config.argument_values['initrd'] + " -append BOOTPARAM "
        elif self.config.argument_values['bios']:
            self.cmd += " -bios " + self.config.argument_values['bios']
        else:
            assert (False), "Must supply either -bios or -kernel or -vm_image option"

        if self.config.argument_values["macOS"]:
            self.cmd = self.cmd.replace("-nographic -net none",
                                        "-nographic -netdev user,id=hub0port0 -device e1000-82545em,netdev=hub0port0,id=mac_vnet0 -cpu Penryn,kvm=off,vendor=GenuineIntel -device isa-applesmc,osk=\"" + self.config.config_values["APPLE-SMC-OSK"].replace("\"", "") + "\" -machine pc-q35-2.4")
            if self.qemu_id == 0:
                self.cmd = self.cmd.replace("-machine pc-q35-2.4", "-machine pc-q35-2.4 -redir tcp:5901:0.0.0.0:5900 -redir tcp:10022:0.0.0.0:22")
        else:
            # self.cmd += " -machine q35 " ## cannot do fast_snapshot
            self.cmd += " -machine kAFL64-v1"
            self.cmd += " -cpu kAFL64-Hypervisor-v1,+vmx"
            # self.cmd += " -cpu kvm64-v1" #,+vmx

        self.fast_vm_reload = True
        if self.fast_vm_reload:
            if qid == 0 or qid == 1337:
                # self.cmd = self.cmd.replace("-display none ", "-vnc :0 ")
                if self.config.argument_values["vm_snapshot"]:
                    self.cmd += " -fast_vm_reload path=%s,load=off,pre_path=%s " % (
                        self.config.argument_values['work_dir'] + "/snapshot/",
                        self.config.argument_values['vm_snapshot'])
                else:
                    self.cmd += " -fast_vm_reload path=%s,load=off " % (
                            self.config.argument_values['work_dir'] + "/snapshot/")
            else:
                self.cmd += " -fast_vm_reload path=%s,load=on " % (
                        self.config.argument_values['work_dir'] + "/snapshot/")
                time.sleep(1)  # fixes some page_cache race bugs?!

        # split cmd into list of arguments for Popen(), replace BOOTPARAM as single element
        self.cmd = [_f for _f in self.cmd.split(" ") if _f]
        c = 0
        for i in self.cmd:
            if i == "BOOTPARAM":
                self.cmd[c] = "nokaslr oops=panic nopti mitigations=off console=ttyS0"
                break
            c += 1

    # Asynchronous exit by slave instance. Note this may be called multiple times
    # while we were in the middle of shutdown(), start(), send_payload(), ..
    def async_exit(self):
        if self.exiting:
            sys.exit(0)

        self.exiting = True
        self.shutdown()

        for tmp_file in [
            self.payload_filename,
            self.tracedump_filename,
            self.control_filename,
            self.binary_filename,
            self.bitmap_filename,
            self.ijonmap_filename]:
            try:
                os.remove(tmp_file)
            except:
                pass

    def shutdown(self):
        logging.info("QEMU%s Shutting down Qemu after %d execs.." % (int(self.qemu_id), self.persistent_runs))

        if not self.process:
            # start() has never been called, all files/shm are closed.
            return 0

        # If Qemu exists, try to graciously read its I/O and SIGTERM it.
        # If still alive, attempt SIGKILL or loop-wait on kill -9.
        output = "<no output received>\n"
        try:
            self.process.terminate()
            output = strdump(self.process.communicate(timeout=1)[0], verbatim=True)
        except:
            pass

        if self.process.returncode is None:
            try:
                self.process.kill()
            except:
                pass

        logging.info("QEMU%s\nQemu exit code: %s" % (self.qemu_id, str(self.process.returncode)))
        header = "\n=================<Qemu %s Console Output>==================\n" % self.qemu_id
        footer = "====================</Console Output>======================\n"
        logging.info(header + output + footer)

        if os.path.isfile(self.qemu_serial_log):
            header = "\n=================<Qemu %s Serial Output>==================\n" % self.qemu_id
            footer = "====================</Serial Output>======================\n"
            serial_out = strdump(read_binary_file(self.qemu_serial_log), verbatim=True)
            logging.info(header + serial_out + footer)

        try:
            # TODO: exec_res keeps from_buffer() reference to kafl_shm
            self.kafl_shm.close()
        except BufferError as e:
            pass

        try:
            self.fs_shm.close()
        except:
            pass

        try:
            os.close(self.kafl_shm_f)
        except:
            pass

        try:
            os.close(self.fs_shm_f)
        except:
            pass

        return self.process.returncode

    def __set_agent(self):
        agent_bin = self.config.argument_values['agent']
        bin = read_binary_file(agent_bin)
        assert (len(bin) <= self.agent_size)
        atomic_write(self.binary_filename, bin)

    def start(self):

        if self.exiting:
            return False

        self.persistent_runs = 0

        # SHM files must exist on Qemu launch
        self.ijon_shm_f     = os.open(self.ijonmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.kafl_shm_f     = os.open(self.bitmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.fs_shm_f       = os.open(self.payload_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)

        os.ftruncate(self.ijon_shm_f, self.ijonmap_size)
        os.ftruncate(self.kafl_shm_f, self.bitmap_size)
        os.ftruncate(self.fs_shm_f, self.payload_size)

        if self.qemu_id not in [0, 1337]:
            final_cmdline = ""
        else:
            final_cmdline = "\n"
            for arg in self.cmd:
                if arg[0] == '-':
                    final_cmdline += '\n\t' + arg
                else:
                    final_cmdline += ' ' + arg

            # delayed Qemu startup - some nasty race condition when launching too many at once
            if self.qemu_id not in [0, 1337]:
                time.sleep(4 + 0.1*float(self.qemu_id))

        logging.info("%s Launching virtual machine...%s" % (self, final_cmdline))

        # Launch Qemu. stderr to stdout, stdout is logged on VM exit
        # os.setpgrp() prevents signals from being propagated to Qemu, instead allowing an
        # organized shutdown via async_exit()
        self.process = subprocess.Popen(self.cmd,
                preexec_fn=os.setpgrp,
                stdin=subprocess.DEVNULL)
                #stdin=subprocess.PIPE,
                #stdout=subprocess.PIPE,
                #stderr=subprocess.STDOUT)

        try:
            self.__qemu_connect()
            self.__qemu_handshake()
        except (OSError, BrokenPipeError) as e:
            if not self.exiting:
                logging.error("%s Failed to launch Qemu: %s" % (self, str(e)))
                self.shutdown()
            return False

        logging.debug("%s Handshake done." % self)

        self.qemu_aux_buffer.set_reload_mode(True)
        self.qemu_aux_buffer.set_timeout(0.8)

        return True

    # release Qemu and wait for it to return
    def run_qemu(self):
        if self.persistent_runs > 0 and self.ecall_id is None:
            print("## NO ECALL ID")
            import traceback
            print("".join(traceback.format_stack()))
        if self.persistent_runs > 0 and len(self.payload_prefix) <= 1:
            print("## NO PREFIX", self.payload_filename, self.payload_size)
            import traceback
            print("".join(traceback.format_stack()))
        self.control.send(b'x')
        self.control.recv(1)

    def wait_qemu(self):
        self.control.recv(1)

    def __qemu_handshake(self):

        self.wait_qemu()

        self.qemu_aux_buffer = QemuAuxBuffer(self.qemu_aux_buffer_filename)
        if not self.qemu_aux_buffer.validate_header():
            logging.error("%s Invalid header in qemu_aux_buffer.py. Abort." % self)
            self.async_exit()

        while self.qemu_aux_buffer.get_state() != 3:
            logging.debug("%s Waiting for target to enter fuzz mode.." % self)
            result = self.qemu_aux_buffer.get_result()
            if result.exec_code == RC.ABORT:
                self.handle_habort()
            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
            self.run_qemu()

        print("self.payload_size: " + str(self.payload_size))
        print("self.payload_filename: " + str(os.path.getsize(self.payload_filename)))


        # Qemu tends to truncate / resize the files. Not sure why..
        assert(self.payload_size == os.path.getsize(self.payload_filename))
        assert(self.bitmap_size == os.path.getsize(self.bitmap_filename))
        assert(self.ijonmap_size == os.path.getsize(self.ijonmap_filename))
        self.kafl_shm = mmap.mmap(self.kafl_shm_f, 0)
        self.c_bitmap = (ctypes.c_uint8 * self.bitmap_size).from_buffer(self.kafl_shm)
        self.fs_shm = mmap.mmap(self.fs_shm_f, 0)

        self.run_qemu()


    def __qemu_connect(self):
        # Note: setblocking() disables the timeout! settimeout() will automatically set blocking!
        self.control = socket.socket(socket.AF_UNIX)
        self.control.settimeout(None)
        self.control.setblocking(1)

        # TODO: Don't try forever, set some timeout..
        while True:
            try:
                self.control.connect(self.control_filename)
                break
            except socket.error:
                if self.process.returncode is not None:
                    raise
            logging.debug("%s Waiting for Qemu connect.." % self)
            time.sleep(0.1)

    def handle_hprintf(self):
        msg = self.qemu_aux_buffer.get_misc_buf()
        msg = msg.decode('latin-1', errors='backslashreplace')

        if self.hprintf_log:
            with open(self.hprintf_logfile, "a") as f:
                f.write(msg)
        elif not self.config.quiet:
            print_hprintf(msg)

    def handle_habort(self):
        msg = self.qemu_aux_buffer.get_misc_buf()
        msg = msg.decode('latin-1', errors='backslashreplace')
        msg = "Guest ABORT: %s" % msg

        logging.error("%s Guest ABORT: %s" % (self, msg))
        if self.hprintf_log:
            with open(self.hprintf_logfile, "a") as f:
                f.write(msg)

        self.run_qemu()
        raise QemuIOException(msg)

    # Fully stop/start Qemu instance to store logs + possibly recover
    def restart(self):

        return True
        self.shutdown()
        # TODO: Need to wait here or else the next instance dies in set_payload()
        # Perhaps Qemu should do proper munmap()/close() on exit?
        time.sleep(0.1)
        return self.start()

    # Reset Qemu after crash/timeout - can skip if target has own forkserver
    def reload(self):
        # don't restart process 0 -> otherwise you'll corrupt the snapshot file 
        return
        if self.config.argument_values['forkserver']:
            return True
        else:
            return self.restart()

    # Wait forever on Qemu to execute the payload - useful for interactive debug
    def debug_payload(self):

        self.set_timeout(0)
        # self.send_payload()
        while True:
            self.run_qemu()
            result = self.qemu_aux_buffer.get_result()
            if result.page_fault:
                logging.warning("Page fault encountered!")
            #            if result.pt_overflow:
            #                logging.warning("PT trashed!")
            if result.hprintf:
                msg = strdump(self.qemu_aux_buffer.get_misc_buf()[:-1], verbatim=True)
                if self.pipe_hprintf:
                    with open(self.qemu_hprintf_log, "w+") as f:
                        f.write(msg)
                else:
                    logging.info("hprintf:\n" + msg)
                continue
            if result.success or result.crash_found or result.asan_found or result.timeout_found:
                break

        logging.info("Result: %s\n" % self.exit_reason(result))
        # self.audit(result)
        return result

    def send_payload(self):
        if self.exiting:
            sys.exit(0)

        result = None
        old_address = 0
        start_time = time.time()
        self.persistent_runs += 1
        # start_time = time.time()

        while True:
            self.run_qemu()

            result = self.qemu_aux_buffer.get_result()

            #            if result.pt_overflow:
            #                logging.warning("PT trashed!")

            if result.exec_code == RC.HPRINTF:
                msg = strdump(self.qemu_aux_buffer.get_misc_buf()[:-1], verbatim=True).rstrip()
                if self.pipe_hprintf:
                    with open(self.qemu_hprintf_log, "w+") as f:
                        f.write(msg)
                else:
                    logging.info("hprintf:\n" + msg)
                logging.info(("QEMU%s hprintf:\n" % self.qemu_id) + msg.rstrip())
                continue

            if result.exec_code == RC.ABORT:
                self.handle_habort()

            if result.exec_done:
                break

            if result.page_fault:
                logging.warn("%s Page fault encountered!" % self)
                if result.page_fault_addr == old_address:
                    logging.error("%s Failed to resolve page after second execution! Qemu status:\n%s" % (self, str(result._asdict())))
                    break
                old_address = result.page_fault_addr
                self.qemu_aux_buffer.dump_page(result.page_fault_addr)

        # record highest seen BBs
        self.bb_seen = max(self.bb_seen, result.bb_cov)

        res = ExecutionResult(
                self.c_bitmap, self.bitmap_size,
                self.exit_reason(result), time.time() - start_time)

        if result.exec_code == RC.STARVED:
            res.starved = True

        if self.qemu_aux_buffer.get_misc_buf().startswith(b"STARVED"):
            res.make_starve_not_crash()

        # self.audit(res.copy_to_array())
        # self.audit(bytearray(self.c_bitmap))

        return res

    def audit(self, bitmap):

        if len(bitmap) != self.bitmap_size:
            logging.info("bitmap size: %d" % len(bitmap))

        new_bytes = 0
        new_bits = 0
        for idx in range(self.bitmap_size):
            if bitmap[idx] != 0x00:
                if self.alt_bitmap[idx] == 0x00:
                    self.alt_bitmap[idx] = bitmap[idx]
                    new_bytes += 1
                else:
                    new_bits += 1
        if new_bytes > 0:
            self.alt_edges += new_bytes
            logging.info("QEMU%s New bytes: %03d, bits: %03d, total edges seen: %03d" % (
                int(self.qemu_id), new_bytes, new_bits, self.alt_edges))

    def exit_reason(self, result):
        if result.exec_code == RC.CRASH:
            return "crash"
        if result.exec_code == RC.TIMEOUT:
            return "timeout"
        elif result.exec_code == RC.SANITIZER:
            return "kasan"
        elif result.exec_code == RC.SUCCESS:
            return "regular"
        elif result.exec_code == RC.STARVED:
            return "regular"
        else:
            raise QemuIOException("Unknown QemuAuxRC code")
    
    def execute_in_trace_mode(self, trace_timeout=None):
        logging.info("QEMU%s Performing trace iteration..." % self.qemu_id)
        exec_res = None
        try:
            self.qemu_aux_buffer.set_trace_mode(True)
            exec_res = self.send_payload()
            self.qemu_aux_buffer.set_trace_mode(False)
        except Exception as e:
            logging.info("QEMU%s Error during trace: %s" % (self.qemu_id, str(e)))
            return None

        return exec_res

    def set_timeout(self, timeout):
        assert (self.qemu_aux_buffer)
        self.qemu_aux_buffer.set_timeout(timeout)

    def get_timeout(self):
        return self.qemu_aux_buffer.get_timeout()

    def execute_in_redqueen_mode(self, payload):
        # execute once to ensure we have all pages
        old_timeout = self.qemu_aux_buffer.get_timeout()
        self.qemu_aux_buffer.set_timeout(0)
        self.set_payload(payload)
        self.send_payload()

        # execute in trace mode, then restore settings
        self.qemu_aux_buffer.set_redqueen_mode(True)
        self.set_payload(payload)  # ensure the payload is intact
        self.run_qemu()

        result = self.qemu_aux_buffer.get_result()
        self.qemu_aux_buffer.set_redqueen_mode(False)
        self.qemu_aux_buffer.set_timeout(old_timeout)

        return ExecutionResult(
            self.c_bitmap, self.bitmap_size,
            self.exit_reason(result), 0)

    def set_ecall_id(self, ecall):
        self.ecall_id = ecall

    def set_payload_prefix(self, prefix):
        self.payload_prefix = prefix

    def set_payload(self, payload):
        # Ensure the payload fits into SHM. Caller has to cut off since they also report findings.
        # actual payload is limited to payload_size - sizeof(uint32) - sizeof(uint8)
        final_payload_len = 1 + len(self.payload_prefix) + len(payload)
        assert final_payload_len <= self.payload_limit + self.prefix_limit, "Payload size %d > SHM limit %d. Check size/shm config" % (final_payload_len, self.payload_limit)

        # if len(payload) > self.payload_limit:
        #    payload = payload[:self.payload_limit]
        try:
            struct.pack_into("=I", self.fs_shm, 0, final_payload_len)
            self.fs_shm.seek(4)
            self.fs_shm.write(bytes([self.ecall_id if self.ecall_id else 0]))
            self.fs_shm.write(self.payload_prefix)
            self.fs_shm.write(payload)
            # self.fs_shm.flush()
        except ValueError:
            if self.exiting:
                sys.exit(0)
            # Qemu crashed. Could be due to prior payload but more likely harness/config is broken..
            logging.info("QEMU%s Failed to set new payload - Qemu crash?" % self.qemu_id)
            raise
