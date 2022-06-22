# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Main logic used by Slaves to push nodes through various fuzzing stages/mutators.
"""

import logging
import time
from array import array

import msgpack

import fuzzer.technique.arithmetic as arithmetic
import fuzzer.technique.bitflip as bitflip
import fuzzer.technique.grimoire_mutations as grimoire
import fuzzer.technique.havoc as havoc
import fuzzer.technique.radamsa as radamsa
import fuzzer.technique.interesting_values as interesting_values
from fuzzer.node import QueueNode
from fuzzer.technique import struct_recovery
from fuzzer.technique.grimoire_inference import GrimoireInference
from fuzzer.technique.redqueen.colorize import ColorizerStrategy
from fuzzer.technique.redqueen.mod import RedqueenInfoGatherer
from fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from fuzzer.technique.trim import perform_trim, perform_center_trim, perform_extend
from fuzzer.technique.helper import rand


class FuzzingStateLogic:
    HAVOC_MULTIPLIER = 5
    RADAMSA_DIV = 10
    COLORIZATION_COUNT = 1
    COLORIZATION_STEPS = 1500
    COLORIZATION_TIMEOUT = 5

    def __init__(self, slave, config):
        self.slave = slave
        self.config = config
        self.grimoire = GrimoireInference(config, self.validate_bytes)
        havoc.init_havoc(config)
        radamsa.init_radamsa(config, self.slave.slave_id)

        self.stage_info = {}
        self.stage_info_start_time = None
        self.stage_info_execs = None
        self.stage_info_findings = 0
        self.attention_secs_start = None
        self.attention_execs_start = None

    def create_limiter_map(self, payload):
        limiter_map = bytearray([1 for _ in range(len(payload))])
        if self.config.argument_values['i']:
            for ignores in self.config.argument_values['i']:
                # log_slave("Ignore-range 0: " + str(ignores[0]) + " " + str(min(ignores[0], len(payload))))
                # log_slave("Ignore-range 1: " + str(ignores[1]) + " " + str(min(ignores[1], len(payload))))
                for i in range(min(ignores[0], len(payload)), min(ignores[1], len(payload))):
                    limiter_map[i] = 0

        return limiter_map

    def stage_timeout_reached(self, limit=20):
        if time.time() - self.stage_info_start_time > limit:
            return True
        else:
            return False

    def create_update(self, new_state, additional_data):
        ret = {}
        ret["state"] = new_state
        ret["attention_execs"] = self.stage_info_execs
        ret["attention_secs"] = time.time() - self.stage_info_start_time
        ret["state_time_initial"] = self.initial_time
        ret["state_time_havoc"] = self.havoc_time
        ret["state_time_splice"] = self.splice_time
        ret["state_time_radamsa"] = self.radamsa_time
        ret["state_time_grimoire"] = self.grimoire_time
        ret["state_time_grimoire_inference"] = self.grimoire_inference_time
        ret["state_time_redqueen"] = self.redqueen_time
        ret["performance"] = self.performance

        if additional_data:
            ret.update(additional_data)

        return ret

    def process_node(self, payload, metadata):
        self.init_stage_info(metadata)

        assert "struct" in metadata
        self.slave.q.set_ecall_id(metadata["struct"]["ecall"])
        self.slave.q.set_payload_prefix(metadata["struct"]["data"])

        if metadata["state"]["name"] == "import":
            self.handle_import(payload, metadata)
            return None, None
        elif metadata["state"]["name"] == "initial":
            new_payload = self.handle_initial(payload, metadata)
            return self.create_update({"name": "struct"}, None), new_payload
        elif metadata["state"]["name"] == "struct":
            old_struct = metadata["struct"].copy()
            struct_info, logging_info = self.handle_struct(payload, metadata)

            if metadata["info"]["parent"] != 0:
                parent_struct = QueueNode.get_metadata(metadata["info"]["parent"])["struct"]
                if old_struct["data"] != struct_info["data"]:
                    if old_struct["data"] == parent_struct["data"]:
                        struct_info["evolved_from_parent"] += 1
                        struct_info["evolved"] += 1
                        print("Struct Evolved ({total}) from parent ({from_parent}) in {node_id}: {old:<64} -> {new:<64}".format(
                            old=parent_struct["data"].decode(), new=struct_info["data"].decode(),
                            total=struct_info["evolved"], from_parent=struct_info["evolved_from_parent"],
                            node_id=metadata["id"]))
                    else:
                        struct_info["evolved"] += 1
                        print("Struct Evolved ({total}) in {node_id}: {old:<64} -> {new:<64}".format(
                            old=parent_struct["data"].decode(), new=struct_info["data"].decode(),
                            total=struct_info["evolved"], node_id=metadata["id"]))

                    struct_info["evolves"].append({
                        "from": old_struct["data"],
                        "to": struct_info["data"],
                        "parent": parent_struct["data"],
                        "payload": payload,
                        "parent_id": metadata["info"]["parent"],
                        "id": metadata["id"],
                        "loop_info": logging_info
                    })

            # suggest new (partly random) payload that fits the required size
            struct_size = struct_info['payload_size']
            new_payload = bytearray(payload)
            del new_payload[struct_size:]
            new_payload.extend(rand.bytes(struct_size - len(new_payload)))

            return self.create_update({"name": "redq/grim"}, {"struct": struct_info}), bytes(new_payload)
        elif metadata["state"]["name"] == "redq/grim":
            grimoire_info = self.handle_grimoire_inference(payload, metadata)
            self.handle_redqueen(payload, metadata)
            return self.create_update({"name": "deterministic"}, {"grimoire": grimoire_info}), None
        elif metadata["state"]["name"] == "deterministic":
            resume, afl_det_info = self.handle_deterministic(payload, metadata)
            if resume:
                return self.create_update({"name": "deterministic"}, {"afl_det_info": afl_det_info}), None
            return self.create_update({"name": "havoc"}, {"afl_det_info": afl_det_info}), None
        elif metadata["state"]["name"] == "havoc":
            self.handle_havoc(payload, metadata)
            return self.create_update({"name": "final"}, None), None
        elif metadata["state"]["name"] == "final":
            self.handle_havoc(payload, metadata)
            return self.create_update({"name": "final"}, None), None
        else:
            raise ValueError("Unknown task stage %s" % metadata["state"]["name"])

    def init_stage_info(self, metadata, verbose=False):
        assert "struct" in metadata
        stage = metadata["state"]["name"]
        nid = metadata["id"]

        self.stage_info["stage"] = stage
        self.stage_info["parent"] = nid
        self.stage_info["method"] = "uncategorized"
        self.stage_info["struct"] = metadata["struct"]

        self.stage_info_start_time = time.time()
        self.stage_info_execs = 0
        self.attention_secs_start = metadata.get("attention_secs", 0)
        self.attention_execs_start = metadata.get("attention_execs", 0)
        self.performance = metadata.get("performance", 0)

        self.initial_time = 0
        self.havoc_time = 0
        self.splice_time = 0
        self.radamsa_time = 0
        self.grimoire_time = 0
        self.grimoire_inference_time = 0
        self.redqueen_time = 0

        self.slave.statistics.event_stage(stage, nid)

        msg = f"Launching {stage} stage on node {nid}"
        if stage != "import":
            fav_bits = len(metadata["fav_bits"])
            speed = metadata["fav_factor"]
            qinfo = f" (fav={fav_bits}, speed={speed})"
        else:
            qinfo = ""
        logging.info(("%s " % self.slave.slave_id) + msg + qinfo)

        if verbose:
            print(f"[Slave {self.slave.slave_id}] {msg}{qinfo}")

    def stage_update_label(self, method):
        self.stage_info["method"] = method
        self.slave.statistics.event_method(method)

    def get_parent_info(self, extra_info=None):
        info = self.stage_info.copy()
        info["parent_execs"] = self.attention_execs_start + self.stage_info_execs
        info["parent_secs"] = self.attention_secs_start + time.time() - self.stage_info_start_time

        if extra_info:
            info.update(extra_info)
        return info

    def handle_import(self, payload: bytes, metadata):
        # X = any ecall, <num> = specific ecall
        ecall_separator = payload.find(b' ')
        ecall_val = payload[:ecall_separator]

        if ecall_val == b'X':
            print("Checking all ecalls for import...")
            ecall_range = range(0, 256)
            payload = payload[ecall_separator + 1:]
        else:
            try:
                ecall_id = int(ecall_val)
                if 0 <= ecall_id < 256:
                    ecall_range = range(ecall_id, ecall_id + 1)
                    print(f"Checking ecall {ecall_id} for import...")
                else:
                    print(f"Ecall id must be in range 0..255, but is {ecall_id}")
                    raise ValueError
                payload = payload[ecall_separator + 1:]
            except:
                print("Unexpected value as ecall, must be X or num in range 0..255. Assuming 'X'.")
                ecall_range = range(0, 256)

        print("Got ecall identifier: ", ecall_val)

        try:
            n = struct_recovery.InputNode.parse_serialized_struct(payload)
            new_struct = n.serialize()
            assert payload.startswith(new_struct)
            metadata["struct"]["data"] = new_struct
            self.slave.q.set_payload_prefix(new_struct)
            payload = payload[len(new_struct):]
        except Exception as ex:
            print(f"Seed without struct ({ex})")

        # TODO: We seem to have some corner case where PT feedback does not
        # work and the seed has to be provided multiple times to actually
        # (eventually) be recognized correctly..
        retries = 1
        if self.config.argument_values["funky"]:
            retries = 8

        for _ in range(retries):
            for ecall_id in ecall_range:
                self.slave.q.set_ecall_id(ecall_id)
                metadata["struct"]["ecall"] = ecall_id
                _, is_new = self.execute(payload, label="import")
                _, is_new = self.execute(payload, label="import", extra_info=metadata)
                if is_new:
                    print(f"Ecall {ecall_id}: New coverage")
                else:
                    print(f"Ecall {ecall_id}: No new coverage")
                # if is_new: break

        # Inform user if seed yields no new coverage. This may happen if -ip0 is
        # wrong or the harness is buggy.
        # if not is_new:
        #     logging.info("QEMU%s Imported payload produced no new coverage, skipping.." % self.slave.slave_id)

    def handle_initial(self, payload, metadata):
        time_initial_start = time.time()

        if self.config.argument_values["trace"]:
            self.stage_update_label("trace")
            self.slave.trace_payload(payload, metadata)

        # self.stage_update_label("calibrate")
        # # Update input performance using multiple randomized executions
        # # Scheduler will de-prioritize execution of very slow nodes..
        # num_execs = 10
        # timer_start = time.time()
        # havoc.mutate_seq_havoc_array(payload, self.execute, num_execs)
        # timer_end = time.time()
        # self.performance = (timer_end-timer_start) / num_execs

        # Trimming only for stable + non-crashing inputs
        if metadata["info"]["exit_reason"] != "regular":  # or metadata["info"]["stable"]:
            logging.info("QEMU%s Validate: Skip trimming.." % self.slave.slave_id)
            return None

        if metadata['info']['starved']:
            return perform_extend(payload, metadata, self.execute, self.slave.payload_size_limit)

        new_payload = perform_trim(payload, metadata, self.execute)

        center_trim = True
        if center_trim:
            new_payload = perform_center_trim(new_payload, metadata, self.execute)

        self.initial_time += time.time() - time_initial_start
        if new_payload == payload:
            return None
        return new_payload

    def _struct_exec_get_fault(self, struct, payload, return_regs=False):
        # print(struct, payload)
        self.slave.q.set_payload_prefix(struct)
        self.slave.q.set_payload(payload)
        res = self.slave.q.send_payload()
        if not res.is_crash():
            if return_regs:
                return res, None, None, None
            else:
                return res, None, None
        fault, struct_extended, *reg_info = self.slave.q.qemu_aux_buffer.get_crashing_struct_info().split(b"|")
        # print(f"Synthesize Info, {res.exit_reason}, {fault}, {reg_info}, {struct_extended}, {payload}")
        if return_regs:
            return res, int(fault, 16), struct_extended.lstrip(), reg_info
        else:
            return res, int(fault, 16), struct_extended.lstrip()

    def handle_struct(self, payload, metadata):
        no_detect_size_field = self.config.argument_values['no_struct_size_detection']
        no_struct_recovery = self.config.argument_values['no_struct_recovery']

        assert "struct" in metadata
        # struct_info = {"data": b"0 0 "}
        # if "struct" in metadata:
        struct_info = metadata["struct"]
        logging_info = []

        struct = struct_info["data"]

        res, fault, struct_extended = self._struct_exec_get_fault(struct, payload)
        if not res.is_crash():
            return struct_info, logging_info

        fixed_ptrs = 0
        while res.is_crash():
            inp = struct_recovery.InputNode.parse_serialized_struct(struct_extended)
            inp.fill_with_data(payload)

            if page := inp.increase_guard_page(fault):
                if not no_detect_size_field:
                    inp = self.handle_struct_size_field(inp, page)
            elif not no_struct_recovery and fixed_ptrs < 1 and inp.make_ptr_from_data(fault):
                fixed_ptrs += 1
            else:
                break

            print("Synthesized struct:", inp.serialize())

            # get adjusted payload if the struct isn't linear
            if inp.childs:
                payload = inp.get_payload()

            res, fault, struct_extended = self._struct_exec_get_fault(inp.serialize(), payload)
            logging_info.append({"fixed_ptrs": fixed_ptrs, "struct_extended": struct_extended, "fault": fault, "payload": inp.get_payload()})

        # noinspection PyUnboundLocalVariable
        # if/while ensure this
        struct_info['data'] = inp.serialize()
        struct_info['payload_size'] = inp.get_payload_size()
        return struct_info, logging_info

    def handle_struct_size_field(self, inp: struct_recovery.InputNode, inc_page: struct_recovery.InputNode):
        if not inc_page.parent:
            # if not 16 <= inc_page.size <= 200:
            return inp

        root = inc_page
        while root.parent:
            root = root.parent
        assert inp is root

        parent = inc_page.parent
        parent_size = parent.size

        # HACK if size is last field and is padded uint32 instead of uint64
        parent.size += -parent.size % 8
        parent.data = parent.data.ljust(parent.size, b'\1')

        parent_page_data = parent.data.copy()

        changed = False
        for idx in range(0, parent.size - 7, 4):
            if idx in parent.childs or idx + 4 in parent.childs:
                continue

            parent.data = parent_page_data.copy()
            parent.data[idx:idx + 8] = inc_page.size.to_bytes(8, 'little')

            res, fault, struct_extended, reg_info = self._struct_exec_get_fault(inp.serialize(), inp.get_payload(), return_regs=True)
            if not res.is_crash() or not inc_page.is_in_guard_page(fault):
                parent.data = parent_page_data.copy()
                parent.data[idx:idx + 8] = (inc_page.size + 1).to_bytes(8, 'little')
                res, fault, struct_extended = self._struct_exec_get_fault(inp.serialize(), inp.get_payload())
                if res.is_crash() and inc_page.is_in_guard_page(fault):
                    # parent.make_field(idx, struct_recovery.StrlenField(next(o for o, c in parent.childs.items() if c == inc_page)))
                    parent.make_field(idx, struct_recovery.SizeofField(next(o for o, c in parent.childs.items() if c == inc_page)))
                    changed = True
                    print("SIZEF FOUND", struct_extended, f"0x{parent.address:x}+{idx} ->", inp.serialize())
                    break
                else:
                    print("SIZEF Failed stage 2", inp.serialize(), inc_page.serialize(), res.exit_reason)

        if not changed:
            parent.size = parent_size
        parent.data = parent_page_data
        return inp

    def handle_grimoire_inference(self, payload, metadata):
        grimoire_info = {}

        if not self.config.argument_values["grimoire"]:
            return grimoire_info
        if len(metadata["new_bytes"]) <= 0 or len(payload) >= 16384:
            return grimoire_info

        self.stage_update_label("grim_inference")
        start_time = time.time()

        generalized_input = self.grimoire.generalize_input(payload, metadata)

        if generalized_input is None:
            return grimoire_info

        grimoire_info["generalized_input"] = generalized_input

        self.grimoire_inference_time = time.time() - start_time
        logging.info("Grimoire generalization took {} seconds".format(self.grimoire_inference_time))
        logging.info("number of unique generalized inputs: {}".format(len(list(self.grimoire.generalized_inputs.keys()))))
        return grimoire_info

    def __perform_grimoire(self, payload, metadata):
        perf = 1 / metadata["performance"]
        grimoire_input = None

        if "grimoire" in metadata:
            if "generalized_input" in metadata["grimoire"]:
                grimoire_input = metadata["grimoire"]["generalized_input"]

        if grimoire_input:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER * 2.0)
            if len(self.grimoire.generalized_inputs) < havoc_amount / 4:
                havoc_amount = len(self.grimoire.generalized_inputs) * 2
            grimoire.havoc(tuple(grimoire_input), self.execute, self.grimoire, havoc_amount, generalized=True)
        else:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER)
            if len(self.grimoire.generalized_inputs) < havoc_amount / 4:
                havoc_amount = len(self.grimoire.generalized_inputs)
            generalized_input = tuple([b''] + [bytes([c]) for c in payload] + [b''])
            grimoire.havoc(generalized_input, self.execute, self.grimoire, havoc_amount, generalized=False)

    def handle_redqueen(self, payload, metadata):

        # if len(metadata["fav_bits"]) < 1:
        #    return
        if 1000 * metadata["info"]["performance"] > 5:
            return

        redqueen_start_time = time.time()
        if self.config.argument_values['redqueen']:
            self.__perform_redqueen(payload, metadata)
        self.redqueen_time += time.time() - redqueen_start_time

    def handle_havoc(self, payload, metadata):
        havoc_afl = True
        havoc_splice = True
        havoc_radamsa = self.config.argument_values['radamsa']
        havoc_grimoire = self.config.argument_values["grimoire"]
        havoc_redqueen = self.config.argument_values['redqueen']
        havoc_struct = self.config.argument_values['struct_size_havoc']
        no_havoc_ptr_loc = self.config.argument_values['no_struct_ptr_loc_havoc']

        for i in range(1):
            initial_findings = self.stage_info_findings

            if not no_havoc_ptr_loc:
                self.__perform_havoc_struct_ptr(payload, metadata)

            # Dict based on RQ learned tokens
            # TODO: AFL only has deterministic dict stage for manual dictionary.
            # However RQ dict and auto-dict actually grow over time. Perhaps
            # create multiple dicts over time and store progress in metadata?
            if havoc_redqueen:
                self.__perform_rq_dict(payload, metadata)

            if havoc_grimoire:
                grimoire_start_time = time.time()
                self.__perform_grimoire(payload, metadata)
                self.grimoire_time += time.time() - grimoire_start_time

            if havoc_radamsa:
                radamsa_start_time = time.time()
                self.__perform_radamsa(payload, metadata)
                self.radamsa_time += time.time() - radamsa_start_time

            if havoc_struct:
                self.__perform_havoc_struct_size(payload, metadata)

            if havoc_afl:
                havoc_start_time = time.time()
                self.__perform_havoc(payload, metadata, use_splicing=False)
                self.havoc_time += time.time() - havoc_start_time

            if havoc_splice:  # and initial_findings == self.stage_info_findings:
                splice_start_time = time.time()
                self.__perform_havoc(payload, metadata, use_splicing=True)
                self.splice_time += time.time() - splice_start_time

        perf = metadata["performance"]
        havoc_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER / perf)
        self.stage_update_label("afl_damage")
        havoc.mutate_seq_damage_byte(payload, self.execute, havoc_amount)
        # self.stage_update_label("afl_dmg_1")
        # havoc.mutate_seq_damage_bit(payload, self.execute, havoc_amount)

        logging.info("QEMU%s HAVOC times: afl: %.1f, splice: %.1f, grim: %.1f, rdmsa: %.1f"
                     % (self.slave.slave_id, self.havoc_time, self.splice_time, self.grimoire_time, self.radamsa_time))

    def validate_bytes(self, payload, metadata, extra_info=None):
        self.stage_info_execs += 1
        # FIXME: can we lift this function from slave to this class and avoid this wrapper?
        parent_info = self.get_parent_info(extra_info)
        return self.slave.validate_bytes(payload, metadata, parent_info)

    def execute(self, payload, label=None, extra_info=None):
        self.stage_info_execs += 1
        if label and label != self.stage_info["method"]:
            self.stage_update_label(label)

        parent_info = self.get_parent_info(extra_info)
        bitmap, is_new = self.slave.execute(payload, parent_info)
        if is_new:
            self.stage_info_findings += 1
        return bitmap, is_new

    def execute_redqueen(self, payload, metadata):
        self.stage_info_execs += 1
        return self.slave.execute_redqueen(payload, metadata)

    def __get_bitmap_hash(self, payload):
        bitmap, _ = self.execute(payload)
        if bitmap is None:
            return None
        return bitmap.hash()

    def __get_bitmap_hash_robust(self, payload):
        hashes = {self.__get_bitmap_hash(payload) for _ in range(3)}
        if len(hashes) == 1:
            return hashes.pop()
        return None

    def __perform_redqueen(self, payload, metadata):
        self.stage_update_label("redq_coloring")

        orig_hash = self.__get_bitmap_hash_robust(payload)
        extension = bytes([207, 117, 130, 107, 183, 200, 143, 154])
        appended_hash = self.__get_bitmap_hash_robust(payload + extension)

        if orig_hash and orig_hash == appended_hash:
            logging.info("QEMU%s Redqueen: Input can be extended" % self.slave.slave_id)
            payload_array = bytearray(payload + extension)
        else:
            payload_array = bytearray(payload)

        colored_alternatives = self.__perform_coloring(payload_array)
        if colored_alternatives:
            payload_array = colored_alternatives[0]
            assert isinstance(colored_alternatives[0], bytearray), print(
                "!! ColoredAlternatives:", repr(colored_alternatives[0]), type(colored_alternatives[0]))
        else:
            logging.info("Redqueen: Input is not stable, skipping..")
            return

        rq_info = RedqueenInfoGatherer()
        rq_info.make_paths(RedqueenWorkdir(self.slave.slave_id, self.config))
        rq_info.verbose = False
        for pld in colored_alternatives:
            if self.execute_redqueen(pld, metadata):
                rq_info.get_info(pld)

        rq_info.get_proposals()
        self.stage_update_label("redq_mutate")
        rq_info.run_mutate_redqueen(payload_array, self.execute)

        # if self.mode_fix_checksum:
        #    for addr in rq_info.get_hash_candidates():
        #        self.redqueen_state.add_candidate_hash_addr(addr)

        # for addr in rq_info.get_boring_cmps():
        #    self.redqueen_state.blacklist_cmp_addr(addr)
        # self.redqueen_state.update_redqueen_blacklist(RedqueenWorkdir(0))

    def dilate_effector_map(self, effector_map, limiter_map):
        ignore_limit = 2
        effector_map[0] = 1
        effector_map[-1] = 1
        for i in range(len(effector_map) // ignore_limit):
            base = i * ignore_limit
            effector_slice = effector_map[base:base + ignore_limit]
            limiter_slice = limiter_map[base:base + ignore_limit]
            if any(effector_slice) and any(limiter_slice):
                for j in range(len(effector_slice)):
                    effector_map[i + j] = 1

    def handle_deterministic(self, payload, metadata):
        if not self.config.argument_values['D']:
            return False, {}

        if len(metadata["fav_bits"]) < 1:
            return False, {}
        if 1000 * metadata["info"]["performance"] > 0.5:
            return False, {}

        skip_zero = self.config.argument_values['s']
        arith_max = self.config.config_values["ARITHMETIC_MAX"]
        use_effector_map = self.config.argument_values['d'] and len(payload) > 128
        limiter_map = self.create_limiter_map(payload)
        effector_map = None

        # Mutable payload allows faster bitwise manipulations
        payload_array = bytearray(payload)

        default_info = {"stage": "flip_1"}
        det_info = metadata.get("afl_det_info", default_info)

        # Walking bitflips
        if det_info["stage"] == "flip_1":
            bitflip.mutate_seq_walking_bits(payload_array, self.execute, skip_null=skip_zero, effector_map=limiter_map)
            bitflip.mutate_seq_two_walking_bits(payload_array, self.execute, skip_null=skip_zero, effector_map=limiter_map)
            bitflip.mutate_seq_four_walking_bits(payload_array, self.execute, skip_null=skip_zero, effector_map=limiter_map)

            det_info["stage"] = "flip_8"
            if self.stage_timeout_reached():
                return True, det_info

        # Walking byte sets..
        if det_info["stage"] == "flip_8":
            # Generate AFL-style effector map based on walking_bytes()
            if use_effector_map:
                logging.info("QEMU%s Preparing effector map.." % self.slave.slave_id)
                effector_map = bytearray(limiter_map)

            bitflip.mutate_seq_walking_byte(payload_array, self.execute, skip_null=skip_zero, limiter_map=limiter_map, effector_map=effector_map)

            if use_effector_map:
                self.dilate_effector_map(effector_map, limiter_map)
            else:
                effector_map = limiter_map

            bitflip.mutate_seq_two_walking_bytes(payload_array, self.execute, effector_map=effector_map)
            bitflip.mutate_seq_four_walking_bytes(payload_array, self.execute, effector_map=effector_map)

            det_info["stage"] = "arith"
            if effector_map:
                det_info["eff_map"] = bytearray(effector_map)
            if self.stage_timeout_reached():
                return True, det_info

        # Arithmetic mutations..
        if det_info["stage"] == "arith":
            effector_map = det_info.get("eff_map", None)
            arithmetic.mutate_seq_8_bit_arithmetic(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            arithmetic.mutate_seq_16_bit_arithmetic(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            arithmetic.mutate_seq_32_bit_arithmetic(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)

            det_info["stage"] = "intr"
            if self.stage_timeout_reached():
                return True, det_info

        # Interesting value mutations..
        if det_info["stage"] == "intr":
            effector_map = det_info.get("eff_map", None)
            interesting_values.mutate_seq_8_bit_interesting(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map)
            interesting_values.mutate_seq_16_bit_interesting(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            interesting_values.mutate_seq_32_bit_interesting(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)

            det_info["stage"] = "done"

        return False, det_info

    def __perform_rq_dict(self, payload_array, metadata):
        rq_dict = havoc.get_redqueen_dict()
        counter = 0
        seen_addr_to_value = havoc.get_redqueen_seen_addr_to_value()
        if len(payload_array) < 256:
            for addr in rq_dict:
                for repl in rq_dict[addr]:
                    if addr in seen_addr_to_value and (
                            len(seen_addr_to_value[addr]) > 32 or repl in seen_addr_to_value[addr]):
                        continue
                    if not addr in seen_addr_to_value:
                        seen_addr_to_value[addr] = set()
                    seen_addr_to_value[addr].add(repl)
                    logging.info("Attempting %s " % repr(repl))
                    for apply_dict in [havoc.dict_insert_sequence, havoc.dict_replace_sequence]:
                        for i in range(len(payload_array) - len(repl)):
                            counter += 1
                            mutated = apply_dict(payload_array, repl, i)
                            self.execute(mutated, label="rq_dict")
        logging.info("RQ-Dict: Have performed %d iters" % counter)

    def __perform_radamsa(self, payload_array, metadata):
        perf = metadata["performance"]
        radamsa_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER / perf) // self.RADAMSA_DIV

        self.stage_update_label("radamsa")
        radamsa.mutate_seq_radamsa_array(payload_array, self.execute, radamsa_amount)

    def __perform_havoc(self, payload_array, metadata, use_splicing):
        perf = metadata["performance"]
        havoc_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER / perf)

        if use_splicing:
            self.stage_update_label("afl_splice")
            # havoc.mutate_seq_splice_array(payload_array, self.execute, havoc_amount)
            havoc.mutate_seq_splice_many(payload_array, self.execute, havoc_amount)
        else:
            self.stage_update_label("afl_havoc")
            havoc.mutate_seq_havoc_array(payload_array, self.execute, havoc_amount)

    def __check_colorization(self, orig_hash, payload_array, min, max):
        backup = payload_array[min:max]
        for i in range(min, max):
            payload_array[i] = rand.int(255)
        new_hash = self.__get_bitmap_hash(payload_array)
        if new_hash is not None and new_hash == orig_hash:
            return True
        else:
            payload_array[min:max] = backup
            return False

    def __colorize_payload(self, orig_hash, payload_array):
        def checker(min_i, max_i):
            self.__check_colorization(orig_hash, payload_array, min_i, max_i)

        c = ColorizerStrategy(len(payload_array), checker)
        t = time.time()
        i = 0
        while True:
            if i >= FuzzingStateLogic.COLORIZATION_STEPS and time.time() - t > FuzzingStateLogic.COLORIZATION_TIMEOUT:  # TODO add to config
                break
            if len(c.unknown_ranges) == 0:
                break
            c.colorize_step()
            i += 1

    def __perform_coloring(self, payload_array):
        orig_hash = self.__get_bitmap_hash_robust(payload_array)
        if orig_hash is None:
            return None

        colored_arrays = []
        for i in range(FuzzingStateLogic.COLORIZATION_COUNT):
            if len(colored_arrays) >= FuzzingStateLogic.COLORIZATION_COUNT:
                assert False  # TODO remove me
            tmpdata = bytearray(payload_array)
            self.__colorize_payload(orig_hash, tmpdata)
            new_hash = self.__get_bitmap_hash(tmpdata)
            if new_hash is not None and new_hash == orig_hash:
                colored_arrays.append(tmpdata)
            else:
                return None

        colored_arrays.append(payload_array)
        return colored_arrays

    def __perform_havoc_struct_size(self, payload, metadata):
        struct = metadata["struct"]["data"]
        inp = struct_recovery.InputNode.parse_serialized_struct(struct)
        inp.fill_with_data(payload)

        meta_copy = msgpack.unpackb(msgpack.packb(metadata, use_bin_type=True), raw=False, strict_map_key=False)

        for f in inp.fields.values():
            for s in range(0x100, inp.childs[f.buffer_offset].size, -1):
                inp.childs[f.buffer_offset].set_size(s)
                meta_copy['struct']['data'] = inp.serialize()
                self.slave.q.set_payload_prefix(meta_copy['struct']['data'])
                meta_copy['struct']['payload_size'] = inp.get_payload_size()
                self.execute(inp.get_payload(), label="struct_havoc", extra_info=meta_copy)

        self.slave.q.set_payload_prefix(struct)

    def __perform_havoc_struct_ptr(self, payload, metadata):
        struct = metadata["struct"]["data"]
        inp = struct_recovery.InputNode.parse_serialized_struct(struct)
        inp.fill_with_data(payload)

        meta_copy = msgpack.unpackb(msgpack.packb(metadata, use_bin_type=True), raw=False, strict_map_key=False)

        def child_iter(n: struct_recovery.InputNode):
            yield from n.childs.values()
            for c in n.childs.values():
                yield from child_iter(c)

        for c in child_iter(inp):
            t_saved = c.type
            for t in 'CIPip':
                if t != t_saved:
                    c.type = t
                    new_struct = inp.serialize()
                    meta_copy['struct']['data'] = new_struct
                    self.slave.q.set_payload_prefix(new_struct)
                    self.execute(inp.get_payload(), label="struct_ptr_havoc", extra_info=meta_copy)
            c.type = t_saved

        self.slave.q.set_payload_prefix(struct)
