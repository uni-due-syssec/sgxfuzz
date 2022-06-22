# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
kAFL Slave Implementation.

Request fuzz input from Master and process it through various fuzzing stages/mutations.
Each Slave is associated with a single Qemu instance for executing fuzz inputs.
"""

import logging
import lz4.frame as lz4
import os
import psutil
import shutil
import signal
import sys
import time

from common.config import FuzzerConfiguration
from common.qemu import qemu
from common.util import read_binary_file, atomic_write
from fuzzer.bitmap import BitmapStorage, GlobalBitmap
from fuzzer.communicator import ClientConnection, MSG_IMPORT, MSG_RUN_NODE, MSG_BUSY
from fuzzer.node import QueueNode
from fuzzer.state_logic import FuzzingStateLogic
from fuzzer.statistics import SlaveStatistics
from fuzzer.technique.helper import rand
from fuzzer.technique import struct_recovery


def slave_loader(slave_id):
    def sigterm_handler(signal, frame):
        if slave_process.q:
            slave_process.q.async_exit()
        sys.exit(0)

    logging.info(("QEMU%s PID: " % slave_id) + str(os.getpid()))
    # sys.stdout = open("slave_%d.out"%slave_id, "w")
    config = FuzzerConfiguration()

    if config.argument_values["cpu_affinity"]:
        psutil.Process().cpu_affinity([config.argument_values["cpu_affinity"]])
    elif config.argument_values["cpu_affinity_offset"]:
        psutil.Process().cpu_affinity([config.argument_values["cpu_affinity_offset"] + slave_id])
    else:
        psutil.Process().cpu_affinity([slave_id])

    connection = ClientConnection(slave_id, config)

    slave_process = SlaveProcess(slave_id, config, connection)

    signal.signal(signal.SIGTERM, sigterm_handler)
    os.setpgrp()

    try:
        slave_process.loop()
    except:
        if slave_process.q:
            slave_process.q.async_exit()
        raise
    logging.info("QEMU%s Exit." % slave_id)


num_funky = 0


def INITIAL_STRUCT():
    return {"data": b"0 0 ", "payload_size": 0, "evolved": 0, "evolved_from_parent": 0, "struct_extended": [], "evolves": [], "fixables": [], "ecall": None}


class SlaveProcess:

    def __init__(self, slave_id, config, connection, auto_reload=False):
        self.config = config
        self.slave_id = slave_id
        self.q = qemu(self.slave_id, self.config,
                      debug_mode=config.argument_values['debug'])
        self.statistics = SlaveStatistics(self.slave_id, self.config)
        self.logic = FuzzingStateLogic(self, self.config)
        self.conn = connection
        self.payload_size_limit = config.config_values['PAYLOAD_SHM_SIZE'] - 5 - config.config_values['PAYLOAD_PREFIX_SHM_SIZE']
        self.timeout_limit_max = 4  # in seconds. TODO: make configurable

        self.bitmap_storage = BitmapStorage(self.config, self.config.config_values['BITMAP_SHM_SIZE'], "master")

    def handle_import(self, msg):
        meta_data = {"state": {"name": "import"}, "id": 0, "struct": INITIAL_STRUCT()}
        payload = msg["task"]["payload"]
        self.logic.process_node(payload, meta_data)
        self.conn.send_ready()

    def handle_busy(self):
        busy_timeout = 1
        kickstart = False

        if kickstart:  # spend busy cycle by feeding random strings?
            logging.info("QEMU%s No ready work items, attempting random.." % self.slave_id)
            start_time = time.time()
            while (time.time() - start_time) < busy_timeout:
                meta_data = {"state": {"name": "import"}, "id": 0, "struct": INITIAL_STRUCT()}
                payload = rand.bytes(rand.int(32))
                self.logic.process_node(payload, meta_data)
        else:
            logging.info("QEMU%s No ready work items, waiting...")
            time.sleep(busy_timeout)
        self.conn.send_ready()

    def handle_node(self, msg):
        meta_data = QueueNode.get_metadata(msg["task"]["nid"])
        assert "struct" in meta_data
        payload = QueueNode.get_payload(meta_data["info"]["exit_reason"], meta_data["id"])

        ## update default timeout in Qemu instance
        t_dyn = 2 * meta_data["info"]["performance"]
        self.q.set_timeout(min(self.timeout_limit_max, t_dyn))

        results, new_payload = self.logic.process_node(payload, meta_data)
        if new_payload:
            default_info = {"method": "validate_bits", "parent": meta_data["id"], "struct": meta_data["struct"]}
            if self.validate_bits(new_payload, meta_data, default_info):
                logging.info("QEMU%s Stage %s found alternative payload for node %d"
                             % (self.slave_id, meta_data["state"]["name"], meta_data["id"]))
            else:
                logging.info("QEMU%s Provided alternative payload found invalid - bug in stage %s?"
                             % (self.slave_id, meta_data["state"]["name"]))
        self.conn.send_node_done(meta_data["id"], results, new_payload)

    def loop(self):
        if not self.q.start():
            return

        logging.info("QEMU%s Started qemu" % self.slave_id)
        while True:
            try:
                msg = self.conn.recv()
            except ConnectionResetError:
                logging.error("QEMU%s Lost connection to master. Shutting down." % self.slave_id)
                return

            if msg["type"] == MSG_RUN_NODE:
                self.handle_node(msg)
            elif msg["type"] == MSG_IMPORT:
                self.handle_import(msg)
            elif msg["type"] == MSG_BUSY:
                self.handle_busy()
            else:
                raise ValueError("Unknown message type {}".format(msg))

    def quick_validate(self, data, info, old_res, quiet=False):
        # Validate in persistent mode. Faster but problematic for very funky targets
        self.statistics.event_exec()
        old_array = old_res.copy_to_array()

        new_res = self.__execute(data, info).apply_lut()
        new_array = new_res.copy_to_array()

        if new_array == old_array:
            return True, new_res.performance

        if not quiet:
            logging.warning("QEMU%s Input validation failed! Target is funky?.." % self.slave_id)
        return False, new_res.performance

    def funky_validate(self, data, info, old_res):
        # Validate in persistent mode with stochastic prop of funky results

        validations = 8
        confirmations = 0
        runtime_avg = 0
        num = 0
        for num in range(validations):
            stable, runtime = self.quick_validate(data, info, old_res, quiet=True)
            if stable:
                confirmations += 1
                runtime_avg += runtime

        if confirmations >= 0.75 * validations:
            return True, runtime_avg / num

        logging.info("QEMU%s Funky input received %d/%d confirmations. Rejecting.." % (self.slave_id, confirmations, validations))
        if self.config.argument_values['v']:
            self.store_funky(data)
        return False, runtime_avg / num

    def store_funky(self, data):
        global num_funky
        num_funky += 1

        # store funky input for further analysis 
        funky_folder = self.config.argument_values['work_dir'] + "/funky/"
        atomic_write(funky_folder + "input_%02d_%05d" % (self.slave_id, num_funky), data)

    def validate_bits(self, data, old_node, default_info):
        new_bitmap, _ = self.execute(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        old_bits.update(old_node["new_bits"])
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def validate_bytes(self, data, old_node, default_info):
        new_bitmap, _ = self.execute(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def execute_redqueen(self, data, metadata):
        self.statistics.event_exec_redqueen()

        if len(data) > self.payload_size_limit:
            data = data[:self.payload_size_limit]
        exec_res = self.q.execute_in_redqueen_mode(data)
        exec_res = self.adjust_res_with_struct_synth(data, metadata, exec_res)
        if not exec_res.is_regular():
            self.statistics.event_reload(exec_res.exit_reason)
            self.q.reload()
        return True

    def __send_to_master(self, data, exec_res, info):
        assert "struct" in info
        info["time"] = time.time()
        info["exit_reason"] = exec_res.exit_reason
        info["performance"] = exec_res.performance
        info["starved"] = exec_res.starved
        if self.conn is not None:
            self.conn.send_new_input(data, exec_res.copy_to_array(), info)

    def trace_payload(self, data, info):
        trace_file_in = self.config.argument_values['work_dir'] + "/redqueen_workdir_%d/pt_trace_results.txt" % self.slave_id;
        trace_folder = self.config.argument_values['work_dir'] + "/traces/"
        trace_file_out = trace_folder + "payload_%05d" % info['id']

        logging.info("QEMU%s Tracing payload_%05d.." % (self.slave_id, info['id']))

        try:
            self.q.set_payload(data)
            exec_res = self.q.execute_in_trace_mode(timeout_detection=False)

            with open(trace_file_in, 'rb') as f_in:
                with lz4.LZ4FrameFile(trace_file_out + ".lz4", 'wb', compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                    shutil.copyfileobj(f_in, f_out)

            if not exec_res.is_regular():
                self.statistics.event_reload(exec_res.exit_reason)
                self.q.reload()
        except Exception as e:
            logging.info("QEMU%s Failed to produce trace %s: %s (skipping..)" % (self.slave_id, trace_file_out, e))
            return None

        return exec_res

    def __execute(self, data: bytes, info, retry=0):
        try:
            self.q.set_payload(data)
            # return self.q.send_payload()
            return self.adjust_res_with_struct_synth(data, info, self.q.send_payload())
        except (ValueError, BrokenPipeError):
            if retry > 2:
                # TODO if it reliably kills qemu, perhaps log to master for harvesting..
                logging.error("QEMU%s Slave aborting due to repeated SHM/socket error." % self.slave_id)
                logging.error("QEMU%s Aborting due to repeated SHM/socket error. Payload: %s" % (self.slave_id, repr(data)))
                raise
            logging.error("QEMU%s SHM/socket error (retry %d)" % (self.slave_id, retry))
            logging.error("QEMU%s SHM/socket error, trying to restart qemu..." % self.slave_id)
            self.statistics.event_reload("shm/socket error")
            if not self.q.restart():
                raise
        return self.__execute(data, info, retry=retry + 1)

    def adjust_res_with_struct_synth(self, data, info, exec_res):
        if exec_res.is_crash() and not exec_res.is_starved():
            try:
                aux_info = self.q.qemu_aux_buffer.get_crashing_struct_info().split(b"|")
                fault, struct_extended, *reg_info = aux_info
                fault, struct_extended = int(fault, 16), struct_extended.lstrip()

                inp = struct_recovery.InputNode.parse_serialized_struct(struct_extended)
                inp.fill_with_data(data)

                if inp.mutate_struct(fault):
                    # We could fix the struct, so it is NOT a real crash
                    # print(f"Fixable crash 0x{fault:x}")
                    exec_res.make_struct_synth_not_crash()
                    info["struct"]["fixables"] = [(fault, struct_extended, reg_info)]
                    return exec_res
                else:
                    # Log the crash info
                    info["struct"]["struct_extended"] = [(fault, struct_extended, reg_info)]
            except Exception as ex:
                print("Cannot process aux buffer,", exec_res.exit_reason)
                import traceback
                traceback.print_exc()
                print(self.q.qemu_aux_buffer.get_crashing_struct_info())
                print(self.q.ecall_id, self.q.payload_prefix, data)
                # raise

        # It either was not a crash, or we cannot fix the crash through struct_synth
        return exec_res

    def execute(self, data, info, validate_timeouts=True):
        assert "struct" in info
        assert "ecall" in info['struct']

        if len(data) > self.payload_size_limit:
            data = data[:self.payload_size_limit]

        exec_res = self.__execute(data, info)
        self.statistics.event_exec(bb_cov=self.q.bb_seen)

        is_new_input = self.bitmap_storage.should_send_to_master(exec_res, exec_res.exit_reason)
        crash = exec_res.is_crash()
        stable = False

        # store crashes and any validated new behavior
        # do not validate timeouts and crashes at this point as they tend to be nondeterministic
        if is_new_input:
            if not crash:
                assert exec_res.is_lut_applied()
                if self.config.argument_values["funky"]:
                    stable, runtime = self.funky_validate(data, info, exec_res)
                    exec_res.performance = runtime
                else:
                    stable, runtime = self.quick_validate(data, info, exec_res)
                    exec_res.performance = (exec_res.performance + runtime) / 2

                if not stable:
                    # TODO: auto-throttle persistent runs based on funky rate?
                    self.statistics.event_funky()
            if validate_timeouts and exec_res.exit_reason == "timeout":
                # re-run timeout payload with max timeout to ensure it is a real timeout.
                # can be quite slow, so we only validate timeouts that also show new edges in reg bitmap
                maybe_new_regular = self.bitmap_storage.should_send_to_master(exec_res, "regular")
                if maybe_new_regular:  ## validate all the timeouts..?
                    dyn_timeout = self.q.get_timeout()
                    # cleanup qemu state, increment timeout exec counter
                    # if crash:
                    #    self.statistics.event_reload(exec_res.exit_reason)
                    #    self.q.reload()
                    self.q.set_timeout(self.timeout_limit_max)
                    # if still new, register the payload as regular or (true) timeout
                    exec_res, is_new = self.execute(data, info, validate_timeouts=False)
                    self.q.set_timeout(dyn_timeout)
                    if is_new and exec_res.exit_reason != "timeout":
                        logging.warning("timeout checker found non-timeout with runtime %f >= %f!" % (exec_res.performance, dyn_timeout))
                    # regular version of this payload is added to reg bitmap, so we can bail out here
                    return exec_res, is_new
            if crash or stable:
                self.__send_to_master(data, exec_res, info)

        # restart Qemu on crash
        if crash:
            self.statistics.event_reload(exec_res.exit_reason)
            self.q.reload()

        return exec_res, is_new_input
