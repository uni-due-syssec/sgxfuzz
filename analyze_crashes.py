#!/usr/bin/env python3
import argparse
import functools
import os
import pty
import random
import re
import struct
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from pprint import pprint
from typing import List

import msgpack
import tqdm
from hexdump import hexdump

from struct_recovery import SizeofField, InputNode

GDB = "gdb"
if os.path.exists("/usr/local/bin/gdb"):
    GDB = "/usr/local/bin/gdb"


class Color:
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    STRIKEOUT = '\033[9m'

    DARKCYAN = '\033[36m'

    GRAY = '\033[90m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'


def read_meta(meta_file):
    with open(meta_file, "rb") as f:
        return msgpack.unpack(f, raw=False, strict_map_key=False)


def is_canonical(addr: int) -> bool:
    return 0 <= addr <= 0x00ffffff_ffffffff or 0xff000000_00000000 <= addr <= 0xffffffff_ffffffff


class CrashInfo:
    def __init__(self, payload_path, meta_path):
        self.payload_path = Path(payload_path)
        self.meta_path = Path(meta_path)
        self.metadata = read_meta(self.meta_path.as_posix())

        self.crash_id = int(self.payload_path.name.rsplit('_', 1)[1])

        # for autocompletion
        self.is_crash: bool = None
        self.is_segv: bool = None
        self.enclave_base: int = None
        self.instruction: str = None
        self.mem_addr = self.mem_expr = self.is_write = None
        self.regs: Registers = None
        self.summary: str = None
        self.gdb_out: str = None
        self.gdb_std_out: bytes = None

    payload = property(lambda self: self.payload_path.read_bytes())  # type: bytes
    struct: bytes = property(lambda self: self.metadata["struct"]["data"])
    struct_extended: bytes = property(lambda self: self.metadata["struct"]["struct_extended"][-1][1])
    meta_fault: int = property(lambda self: self.metadata["struct"]["struct_extended"][-1][0])
    parent = property(lambda self: self.metadata["info"]["parent"])
    runner_input: bytes = property(lambda self: bytes([self.ecall]) + self.struct + self.payload)
    instruction_address: int = property(lambda self: self.regs.rip - self.enclave_base)
    test_name: str = property(lambda self: f"test_{self.crash_id:05}")
    ecall: int = property(lambda self: int(self.metadata["struct"]["ecall"]))

    def get_input_node(self):
        self._input_node = InputNode.parse_serialized_struct(self.struct_extended)
        assert self.struct == self._input_node.serialize(), f"{self.struct} == {self._input_node.serialize()}"
        self._input_node.fill_with_data(self.payload)
        return self._input_node

    def get_gdb_input_node(self):
        self._gdb_input_node = InputNode.parse_serialized_struct(self.gdb_std_out[:self.gdb_std_out.index(b"\n")])
        assert self.struct == self._gdb_input_node.serialize(), f"{self.struct} == {self._gdb_input_node.serialize()}"
        self._gdb_input_node.fill_with_data(self.payload)
        return self._gdb_input_node


class WriteableCrashInfo:
    def __init__(self, base_crashinfo: CrashInfo):
        self.base = base_crashinfo
        self.payload = self.base.payload
        self.struct = self.base.struct
        self.test_name = f"{self.base.test_name}_{random.getrandbits(16):04x}"
        self.is_crash = self.base.is_crash
        self.is_segv = self.base.is_segv
        self.ecall = self.base.ecall

        # for autocompletion
        self.enclave_base: int = None
        self.instruction: str = None
        self.mem_addr = self.mem_expr = self.is_write = None
        self.regs: Registers = None

    runner_input = CrashInfo.runner_input
    instruction_address = CrashInfo.instruction_address


class Registers:
    def __init__(self):
        self.rax = self.rbx = self.rcx = self.rdx = self.rsi = self.rdi = self.rbp = self.rsp = self.rip = self.eflags = self.cs = self.ss = self.ds = self.es = self.fs = self.gs = None

    @classmethod
    def parse(cls, gdb_regs):
        r = cls()
        for m in re.finditer(r"^([a-z]+1?\d?)\s+(0x[\da-f]+)", gdb_regs, re.M):
            setattr(r, m.group(1), int(m.group(2), 16))
        return r


@dataclass
class ProcMapEntry:
    start: int
    end: int
    perm: str
    typ: str
    size: int
    label: str


class ProcMap:
    def __init__(self, proc_map_file):
        self.proc_map_file = Path(proc_map_file)

        self.proc_map = self.parse(self.proc_map_file.read_text())

    @staticmethod
    def parse(proc_map_text):
        pmap = []
        for line in proc_map_text.splitlines():
            m = re.match(r'([\da-f]+)-([\da-f]+) ([rwx-]{3})(.) ([\da-f]+) \d+:\d+ \d+\s+(.*)', line)
            assert m
            start, end, perm, t, size, label = m.groups()
            pmap.append(ProcMapEntry(int(start, 16), int(end, 16), perm, t, size, label))
        return pmap

    def find(self, addr):
        return next((p for p in self.proc_map if p.start <= addr < p.end), None)


def child_iter(n: InputNode):
    yield from n.childs.values()
    for c in n.childs.values():
        yield from child_iter(c)


class PostAnalysis:
    def __init__(self, evaldir: Path):
        self.evaldir = evaldir

        self.workdir = evaldir.joinpath("sgx_workdir")
        self.test_dir = self.workdir.joinpath("test_dir")
        self.target = evaldir.joinpath("fuzz-generic").absolute()
        self.ecall = None

        self.proc_map = ProcMap(self.workdir.joinpath("dump/proc_maps.txt"))

        self.test_dir.mkdir(exist_ok=True)

        print("Crash analysis", self.evaldir.absolute().name)

    def run(self, crashinfo: CrashInfo):
        cmd = [self.target.as_posix()]
        if self.ecall is not None:
            cmd.append(str(self.ecall))
        p = subprocess.Popen(cmd, cwd=self.evaldir.as_posix(), env={"LD_LIBRARY_PATH": "."}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdin.write(crashinfo.runner_input[:0x1000])  # Trim to max payload size
        p.stdin.close()

        crashinfo.exit_code, crashinfo.stdout, crashinfo.stderr = p.wait(), p.stdout.read(), p.stderr.read()
        return crashinfo.exit_code

    def run_gdb(self, crashinfo: CrashInfo):
        test_payload_path = self.test_dir.joinpath(crashinfo.test_name)
        test_payload_path.write_bytes(crashinfo.runner_input)

        def gdb_ex(*cmds):
            def _gen(cmds):
                for c in cmds:
                    yield "-ex"
                    yield c

            return list(_gen(cmds))

        pty_r, pty_w = pty.openpty()
        pty_path = os.readlink(f"/proc/self/fd/{pty_w}")

        ecall = self.ecall
        if ecall is None:
            ecall = ""
        p = subprocess.Popen(
            [GDB, "-q", "-nh"
             ] + gdb_ex(
                "set disassembly-flavor intel",
                "set confirm off",
                "set pagination off",
                f"tty {pty_path}",
                "handle SIGILL nostop",
                "b signal_abort",
                f'r {ecall} < "{test_payload_path.absolute().as_posix()}"',
                "p/x enclave_start",
                r'printf "FAULTADDRESS 0x%llx\n", $_siginfo._sifields._sigfault.si_addr',
                'p "REGS START"', 'i r', 'p "REGS END"',
                "disas $rip,+10",
                'p "CONTEXT_START"', "p/x context->uc_mcontext.gregs[REG_RIP]", "disas context->uc_mcontext.gregs[REG_RIP],+10", 'p "CONTEXT_END"',
                # "p/x context->uc_mcontext.gregs[REG_RAX]",
                "x/50gx $rsp",
                "kill",
                "quit",
            ) + [self.target.as_posix()],
            cwd=self.evaldir.as_posix(), env={"LD_LIBRARY_PATH": ".", "HOME": "/tmp/gdb"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        crashinfo.gdb_out = out = out.decode()
        # print(out)

        os.close(pty_w)
        gdb_std_out = b""
        try:
            while r := os.read(pty_r, 1000):
                gdb_std_out += r
        except OSError:
            pass
        crashinfo.gdb_std_out = gdb_std_out

        if re.search("Inferior .* exited normally", out, re.M):
            crashinfo.is_crash = False
            # assert crashinfo.exit_code >= 0, f"No crash in gdb, only normal ({crashinfo.exit_code})"
            return "No crash in gdb"
        elif re.search("Breakpoint.*signal_abort", out, re.M):
            # assert crashinfo.exit_code == -4, "Normal run wasn't SIGILL"
            sigill_info = out.split("CONTEXT_START", 1)[1].split("CONTEXT_END", 1)[0]
            crashinfo.is_crash = True
            crashinfo.enclave_base = int(re.search(r"\$1 = (0x[0-9a-f]+)", out, flags=re.I).group(1), 16)
            crashinfo.regs = Registers()
            crashinfo.regs.rip = int(re.search(r"\$\d+ = (0x[0-9a-f]+)", sigill_info, flags=re.I).group(1), 16)
            crashinfo.instruction = ins = re.search(r'^ {3}[^:]*:(.*$)', sigill_info, flags=re.I | re.M).group(1).strip()

            return f"SIGILL 0x{crashinfo.instruction_address:08x}: {ins + ',':<35} "

        assert re.search("Inferior .* killed", out, re.M), "Unexpected exit in GDB"
        crashinfo.is_crash = True
        crashinfo.is_segv = True
        # assert getattr(crashinfo, "exit_code", -11) == -11, "Normal run wasn't SEGV"

        crashinfo.enclave_base = int(re.search(r"\$1 = (0x[0-9a-f]+)", out, flags=re.I).group(1), 16)
        crashinfo.regs = regs = Registers.parse(out.split("REGS START", 1)[1].split("REGS END", 1)[0])
        fault_address = int(re.search(r"FAULTADDRESS (0x[0-9a-f]+)", out, flags=re.I).group(1), 16)

        ins = re.search(r'^=>[^:]*:(.*$)', out, flags=re.I | re.M).group(1).strip()
        crashinfo.instruction = ins
        if ins.count("PTR") == 1 and (m := re.search(r'PTR (?:es:|ds:)?\[([a-z0-9+*-]+)]', ins)):
            mem_expr = m.group(1)
            mem_addr = eval(mem_expr, {k: v for k in dir(regs) if isinstance(v := getattr(regs, k), int)})
            write = ins.startswith("mov") and ins.index("PTR") < ins.index(",")

            if mem_addr > 1 << 64:
                print(f"WARNING: Integer overflow ({mem_addr:#x})")
                mem_addr &= 0xffff_ffff_ffff_ffff

            if fault_address > 0 and mem_addr != fault_address:
                print(f"WARNING: Calculated fault ({mem_addr:#x}) != SigInfo ({fault_address:#x})")

            crashinfo.mem_addr = mem_addr
            crashinfo.mem_expr = mem_expr
            crashinfo.is_write = write

            info = f"0x{crashinfo.instruction_address:08x}: {ins + ',':<35} " + ["    ", "(W) "][write] + f'({mem_expr})'.ljust(10) + f" = 0x{mem_addr:012x}"
        elif fault_address > 0 and 2 == len(mem_expr := re.findall(r'PTR (?:es:|ds:)?\[([a-z0-9+*-]+)]', ins)):  # Double pointer instruction and canonical address
            mem_addr = [eval(m, {k: v for k in dir(regs) if isinstance(v := getattr(regs, k), int)}) for m in mem_expr]
            if sum(a == fault_address for a in mem_addr) == 1:
                for i, (e, a) in enumerate(zip(mem_expr, mem_addr)):
                    if a == fault_address:
                        crashinfo.mem_addr = a
                        crashinfo.mem_expr = e
                        crashinfo.is_write = i == 0
                        info = f"0x{crashinfo.instruction_address:08x}: {ins + ',':<35} " + ["    ", "(W) "][crashinfo.is_write] + f'({e})'.ljust(10) + f" = 0x{a:012x}"
                        break
                else:
                    assert False, "Shouldn't be here"
            else:
                crashinfo.mem_addr = fault_address
                info = f"0x{crashinfo.instruction_address:08x}: {ins}"
        elif fault_address == 0 and 2 == len(mem_expr := re.findall(r'PTR (?:es:|ds:)?\[([a-z0-9+*-]+)]', ins)):  # Double pointer instruction and non-canonical address
            mem_addr = [eval(m, {k: v for k in dir(regs) if isinstance(v := getattr(regs, k), int)}) for m in mem_expr]
            if sum((not is_canonical(a)) + (a == 0) for a in mem_addr) == 1:
                for i, (e, a) in enumerate(zip(mem_expr, mem_addr)):
                    if not is_canonical(a) or a == 0:
                        crashinfo.mem_addr = a
                        crashinfo.mem_expr = e
                        crashinfo.is_write = i == 0
                        info = f"0x{crashinfo.instruction_address:08x}: {ins + ',':<35} " + ["    ", "(W) "][crashinfo.is_write] + f'({e})'.ljust(10) + f" = 0x{a:012x}"
                        break
                else:
                    assert False, "Shouldn't be here"
            else:
                assert False, f"ERROR: Cannot determine fault address (2) ({ins})"
        elif "PTR" not in ins and (m := re.match(r'(?:jmp|call)\s*([a-z0-9]+)', ins)):
            mem_expr = m.group(1)
            mem_addr = eval(mem_expr, {k: v for k in dir(regs) if isinstance(v := getattr(regs, k), int)})

            crashinfo.mem_addr = mem_addr
            crashinfo.mem_expr = mem_expr
            crashinfo.is_write = False

            info = f"0x{crashinfo.instruction_address:08x}: {ins + ',':<35} " + "(X) " + f'({mem_expr})'.ljust(10) + f" = 0x{mem_addr:012x}"
        elif fault_address > 0:
            crashinfo.mem_addr = fault_address
            info = f"0x{crashinfo.instruction_address:08x}: {ins}"
        else:
            info = f"0x{crashinfo.instruction_address:08x}: {ins}"
            assert False, f"ERROR: Cannot determine fault address ({ins})"

        return info

    def generate_testcases(self):
        meta_path = self.workdir.joinpath("metadata")
        for folder in ["crash", "kasan", "regular", "timeout"]:
            for crash_path in sorted(self.workdir.joinpath(f"corpus/{folder}").glob("payload_*")):
                crash_id = int(crash_path.name.rsplit('_', 1)[1])

                crashinfo = CrashInfo(crash_path, meta_path.joinpath(f"node_{crash_id:05}"))
                test_payload_path = self.test_dir.joinpath(crashinfo.test_name)
                test_payload_path.write_bytes(crashinfo.runner_input)

    def generate_c_source(self):
        meta_path = self.workdir.joinpath("metadata")
        for crash_path in sorted(self.workdir.joinpath(f"corpus/crash").glob("payload_*")):
            crash_id = int(crash_path.name.rsplit('_', 1)[1])
            crashinfo = CrashInfo(crash_path, meta_path.joinpath(f"node_{crash_id:05}"))

            try:
                inp = crashinfo.get_input_node()
            except AssertionError as ex:
                import traceback
                traceback.print_exc()
                continue

            def post_iter(node: InputNode, prefix):
                for i, c in node.childs.items():
                    yield from post_iter(c, f"{prefix}_{c.getType()}{i}")
                yield node, prefix

            data = []
            assigns = []
            for c, p in post_iter(inp, "input"):  # type: InputNode, str
                data.append(f"unsigned char {p}[] = {{{', '.join(map(hex, c.data))}}};")
                for i, ci in c.childs.items():
                    assigns.append(f"*(unsigned char**)&{p}[{i}] = {p}_{ci.getType()}{i};")
                for i, fi in c.fields.items():
                    if isinstance(fi, SizeofField):
                        assigns.append(f"*(unsigned long long int*)&{p}[{i}] = sizeof({p}_C{fi.buffer_offset});")
                    else:
                        assert False, f"Unknown type: {type(fi)}"
            with self.test_dir.joinpath(f"input_{crash_id:05}.h").open("w") as f:
                f.write("/*\n")
                inp.show(f)
                f.write("*/\n\n")
                f.write("\n".join(data + [""]) + "\n")
                f.write("const char* get_input() {\n\t" + "\n\t".join(assigns) + "\n\treturn (const char*)input;\n}\n")
                f.write(f'int get_ecall() {{ return {crashinfo.ecall}; }}\n')

    def main_analysis(self, selected_crash_id: List[int] = None):
        crashes = []

        meta_path = self.workdir.joinpath("metadata")
        for crash_path in sorted(self.workdir.joinpath("corpus/crash").glob("payload_*")):
            crash_id = int(crash_path.name.rsplit('_', 1)[1])
            if selected_crash_id is not None and crash_id not in selected_crash_id:
                continue

            crashinfo = CrashInfo(crash_path, meta_path.joinpath(f"node_{crash_id:05}"))

            try:
                crashinfo.meta_fault
            except (KeyError, IndexError):
                print(f"Crash {crash_id:05} Cannot read fault from metadata")
                continue

            if arg_parse().no_null and (
                    crashinfo.meta_fault < 0x100 and (b'\0' * 7) in crashinfo.payload
                    # or struct.pack('<Q', crashinfo.meta_fault) in crashinfo.payload
            ):
                continue
            if arg_parse().no_lower_p and b'p' in crashinfo.struct:
                continue
            if arg_parse().no_large_diff and any(struct.pack('P', crashinfo.meta_fault - d) in crashinfo.payload for d in range(0x1000)):
                continue
            if arg_parse().no_super_large_diff and any((crashinfo.meta_fault - 0x1000000) <= struct.unpack('<Q', crashinfo.payload[i:i + 8])[0] <= (crashinfo.meta_fault + 0x1000000) for i in range((len(crashinfo.payload) - 8) + 1)):
                continue
            if arg_parse().no_ptr_0x7ff and any(0x7fff00000000 <= struct.unpack('<Q', crashinfo.payload[i:i + 8])[0] <= 0x7fffffffffff for i in range((len(crashinfo.payload) - 8) + 1)):
                continue
            crashes.append(crashinfo)

            try:
                exit_code = self.run(crashinfo)

                result = [
                    f"crash_{crash_id:05}",
                    f"E{crashinfo.ecall}".ljust(4),
                    f'{ {-11: "SEGV"}.get(exit_code, exit_code):4}',
                ]

                if exit_code > 0:
                    result = [f"OCALL ({exit_code})"]
                elif exit_code == -11:  # SIGSEGV
                    info = self.run_gdb(crashinfo)
                    assert crashinfo.is_segv, f"SEGV only in normal run ({info})"

                    debug = []
                    node = crashinfo.get_input_node()
                    gdb_node = crashinfo.get_gdb_input_node()
                    if node.is_in_guard_page(crashinfo.meta_fault) or any(c.is_in_guard_page(crashinfo.meta_fault) for c in child_iter(node)) \
                            or gdb_node.is_in_guard_page(crashinfo.mem_addr) or any(c.is_in_guard_page(crashinfo.mem_addr) for c in child_iter(gdb_node)):
                        mutate_info = "M:G"
                    else:
                        mutate = node.make_ptr_from_data(crashinfo.mem_addr, debug=debug)
                        mutate_info = "M:" + str(mutate)[0] + " "
                        if debug[0]:
                            mutate_info += "=" + str(len(debug[0]))
                        if debug[1]:
                            mutate_info += "~" + str(len(debug[1]))
                        if not mutate and not debug[0] and not debug[1]:
                            mutate_info = None

                    # min_diff=
                    # for i in range(len(crashinfo.payload)):
                    #
                    # min(crashinfo.meta_fault-struct.unpack('Q',  crashinfo.payload[i:i+8]) for i in  if )

                    result.extend([
                        f'0x{(crashinfo.instruction_address + 0x555555854000):08x}',
                        f'// {info}',
                    ])
                    if mutate_info:
                        result.append(f"({mutate_info.strip()})")

                    if section := self.proc_map.find(crashinfo.mem_addr or -1):
                        result.append(f"{section.label or '<>'} ({section.perm})")
                    elif section := self.proc_map.find(crashinfo.mem_addr - 1 or -1):
                        result.append(f"Eof {section.label or '<>'} ({section.perm})")
                elif exit_code < 0:
                    result.append(self.run_gdb(crashinfo))
                result.append(f'|| {hex(crashinfo.meta_fault)}, {crashinfo.struct_extended}')
            except AssertionError as ex:
                result = [f"crash_{crash_id:05} ERROR {ex.__class__.__name__}: {ex}"]
            except Exception:
                import traceback
                traceback.print_exc()
                result = [f"crash_{crash_id:05} ERROR"]
            result = " ".join(result)
            crashinfo.summary = result

            if selected_crash_id is None or len(selected_crash_id) > 1:
                print(result)

        if selected_crash_id is None:
            with self.evaldir.joinpath("crash-analysis.log").open("w") as log:
                for c in crashes:
                    log.write(c.summary + "\n")

        return crashes

    @staticmethod
    def clean_data(data):
        if isinstance(data, list):
            if len(data) > 100:
                data[10:-10] = ["..."]
            else:
                for d in data:
                    PostAnalysis.clean_data(d)
        if isinstance(data, dict):
            for d in data.values():
                PostAnalysis.clean_data(d)
        return data

    def detailed_eval(self, base_crashinfo: CrashInfo):
        log_f = self.test_dir.joinpath(base_crashinfo.test_name + ".log").open("w")

        def out(*args, display=None):
            print(*(display or args))
            print(*args, file=log_f)

        out("Details:", base_crashinfo.summary)
        if not arg_parse().skip_dump:
            out("Payload:")
            hexdump(base_crashinfo.payload)

            out("\nStruct:")
            n = InputNode.parse_serialized_struct(base_crashinfo.struct_extended)
            try:
                assert n.serialize() == base_crashinfo.struct, f"{n.serialize()} == {base_crashinfo.struct}"
            except AssertionError as ex:
                out("Warning:", ex.__class__.__name__, ex)
            n.fill_with_data(base_crashinfo.payload)
            n.show()
            n.show(file=log_f)

            out("\nMetadata:")
            pprint(PostAnalysis.clean_data(base_crashinfo.metadata), compact=False, width=200)

        if not arg_parse().skip_byte_analysis:
            self.analyze_payload_bytes(base_crashinfo, out)
        if not arg_parse().skip_struct_analysis:
            self.analyze_struct_ptr(base_crashinfo, out)

        log_f.close()

    def analyze_payload_bytes(self, base_crashinfo: CrashInfo, print=print):
        print("\nAnalyze Payload Bytes")
        if not base_crashinfo.is_crash:
            print("Non-crash, stopping.")
            return

        n = InputNode.parse_serialized_struct(base_crashinfo.struct)

        crash_test = WriteableCrashInfo(base_crashinfo)
        mem_addresses = set()
        ins_addresses = set()
        for _ in tqdm.trange(10):
            self.run_gdb(crash_test)
            mem_addresses.add(crash_test.mem_addr)
            ins_addresses.add(crash_test.instruction_address)
            if not crash_test.is_crash:
                print("Crash funky, stopping.")
                return

        stable_mem = len(mem_addresses) == 1
        stable_addr = len(ins_addresses) == 1
        if not stable_mem:
            print(f"Memory Address unstable ({', '.join(hex(a) for a in mem_addresses)})")
        if not stable_addr:
            print(f"Instruction Address unstable ({', '.join(hex(a) for a in ins_addresses)})")

        if stable_mem or stable_addr:
            def check_byte(i):
                crash_test = WriteableCrashInfo(base_crashinfo)
                crash_test.payload = bytearray(base_crashinfo.payload)
                crash_test.payload[i] = ~crash_test.payload[i] & 0xff
                self.run_gdb(crash_test)

                if not crash_test.is_crash or not base_crashinfo.is_crash:
                    return crash_test.is_crash != base_crashinfo.is_crash, False, False
                return (crash_test.is_crash != base_crashinfo.is_crash,
                        stable_addr and crash_test.instruction_address != base_crashinfo.instruction_address,
                        stable_mem and crash_test.mem_addr != base_crashinfo.mem_addr)

            with ThreadPoolExecutor(max_workers=min(32, os.cpu_count() * 2)) as p:
                important_bytes = {i: x for i, x in zip(tqdm.trange(len(base_crashinfo.payload)), p.map(check_byte, range(min(n.get_payload_size(), len(base_crashinfo.payload))))) if any(x)}
            # print("Important Bytes:", list(important_bytes.keys()))
            dump = """{}: changes is_crash
[]: changes crash ip
(): changes crash fault
~~: ignored
"""
            for i, b in enumerate(base_crashinfo.payload):
                if i > 0 and i % 16 == 0:
                    dump += "\n"
                if i % 16 == 0:
                    dump += f"{i:04x}:"
                if i % 8 == 0:
                    dump += " "
                if i in important_bytes:
                    if important_bytes[i][0]:
                        dump += f"{{{b:02x}}}".upper()
                    elif important_bytes[i][1]:
                        dump += f"[{b:02x}]".upper()
                    elif important_bytes[i][2]:
                        dump += f"({b:02x})".upper()
                elif i >= n.get_payload_size():
                    dump += f"~{b:02x}~"
                else:
                    dump += f" {b:02x} "
            display = dump
            display = re.sub(r'(\(.*?\))', Color.GREEN + r'\1' + Color.END, display)
            display = re.sub(r'({.*?})', Color.RED + r'\1' + Color.END, display)
            display = re.sub(r'(~.*?~)', Color.GRAY + r'\1' + Color.END, display)
            display = re.sub(r'(\[[^[]*?\])', Color.YELLOW + r'\1' + Color.END, display)
            print(dump, display=[display])

    def analyze_struct_ptr(self, base_crashinfo: CrashInfo, print=print):
        print("\nAnalyze Struct Pointer", display=[f"\n{Color.BOLD}Analyze Struct Pointer{Color.END}"])

        def struct_diff(a_c: CrashInfo, b_c: CrashInfo):
            a_s: str = a_c.struct.decode().strip()
            b_s: str = b_c.struct.decode().strip()
            assert len(a_s) == len(b_s)
            diff = ""
            for a, b in zip(a_s, b_s):
                if a == b:
                    diff += a
                else:
                    diff += f"[{a}{b}]"
            return diff

        n = InputNode.parse_serialized_struct(base_crashinfo.struct)
        crash_test = WriteableCrashInfo(base_crashinfo)
        found_smth = False
        for c in child_iter(n):
            t_saved = c.type
            for t in 'CIiPp':
                c.type = t
                crash_test.struct = n.serialize()
                self.run(crash_test)
                if crash_test.exit_code != base_crashinfo.exit_code:
                    found_smth = True
                    print(struct_diff(base_crashinfo, crash_test), f"Exit Code: {base_crashinfo.exit_code} -> {crash_test.exit_code}")
                if crash_test.exit_code == base_crashinfo.exit_code == -11:
                    self.run_gdb(crash_test)
                    if base_crashinfo.instruction_address != crash_test.instruction_address:
                        found_smth = True
                        print(struct_diff(base_crashinfo, crash_test), f"IP: 0x{base_crashinfo.instruction_address:08x} -> 0x{crash_test.instruction_address:08x}")
                    elif base_crashinfo.mem_addr != crash_test.mem_addr:
                        found_smth = True
                        print(struct_diff(base_crashinfo, crash_test), f"Fault: 0x{base_crashinfo.mem_addr:08x} -> 0x{crash_test.mem_addr:08x}")
            c.type = t_saved

        if not found_smth:
            print("Nothing found")


@functools.lru_cache
def arg_parse():
    arg = argparse.ArgumentParser()
    arg.add_argument("evaldir", default=".", nargs='?')
    arg.add_argument("details_for", nargs="*")
    arg.add_argument("--generate-tests", "-t", action="store_true", default=False)
    arg.add_argument("--generate-c-source", "-c", action="store_true", default=False)
    arg.add_argument("--skip-dump", "-d", action="store_true", default=False)
    arg.add_argument("--skip-byte-analysis", "-b", action="store_true", default=False)
    arg.add_argument("--skip-struct-analysis", "-s", action="store_true", default=False)
    arg.add_argument("--no-null", "-0", action="store_true", default=False)
    arg.add_argument("--no-lower-p", "--np", action="store_true", default=False)
    arg.add_argument("--no-large-diff", action="store_true", default=False)
    arg.add_argument("--no-super-large-diff", action="store_true", default=False)
    arg.add_argument("--no-ptr-0x7ff", action="store_true", default=False)

    return arg.parse_args()


def main():
    args = arg_parse()
    evaldir = Path(args.evaldir)
    if not evaldir.joinpath("sgx_workdir").is_dir():
        print(f"sgx_workdir not found!")
        exit(1)

    analysis = PostAnalysis(evaldir)

    if args.generate_tests:
        analysis.generate_testcases()
        exit(0)
    if args.generate_c_source:
        analysis.generate_c_source()
        exit(0)

    all_crashes = not args.details_for or args.details_for[0].lower() == "all"
    crashes = analysis.main_analysis(None if all_crashes else list(map(int, args.details_for)))

    if not crashes:
        print("No Crashes found!")
        exit()

    if args.details_for:
        for c in crashes:
            analysis.detailed_eval(c)


if __name__ == '__main__':
    main()
