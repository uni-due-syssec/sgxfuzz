#!/usr/bin/env python3

import hashlib
import random
import re
import struct
import subprocess
import sys
from base64 import b16decode
from collections import deque
from pathlib import Path

import tqdm
from pygdbmi.gdbcontroller import GdbController


# flags: (common/inc/internal/arch.h)
# SI_FLAG_NONE                0x0
# SI_FLAG_R                   0x1             /* Read Access */
# SI_FLAG_W                   0x2             /* Write Access */
# SI_FLAG_X                   0x4             /* Execute Access */
# SI_FLAG_PT_LOW_BIT          0x8                             /* PT low bit */
# SI_FLAG_PT_MASK             (0xFF<<SI_FLAG_PT_LOW_BIT)      /* Page Type Mask [15:8] */
# SI_FLAG_SECS                (0x00<<SI_FLAG_PT_LOW_BIT)      /* SECS */
# SI_FLAG_TCS                 (0x01<<SI_FLAG_PT_LOW_BIT)      /* TCS */
# SI_FLAG_REG                 (0x02<<SI_FLAG_PT_LOW_BIT)      /* Regular Page */
# SI_FLAG_TRIM                (0x04<<SI_FLAG_PT_LOW_BIT)      /* Trim Page */
# SI_FLAG_PENDING             0x8
# SI_FLAG_MODIFIED            0x10
# SI_FLAG_PR                  0x20

def dump_pages(enclave: str, out_dir: str, sgx_sign_exe: str, dump_range=None, total_size=0):
    assert Path(enclave).exists()
    assert Path(out_dir).is_dir()
    assert Path(sgx_sign_exe).exists()

    sgx_sign_exe = Path(sgx_sign_exe).absolute().as_posix()

    port = random.randint(10_000, 60_000)
    print(f"PORT {port}")
    wineprefix = f"/tmp/sgxdumpwine/"
    sgx_sign = subprocess.Popen(["wine64", "winedbg", "--gdb", "--no-start",
                                 "--port", str(port),
                                 sgx_sign_exe, "gendata",
                                 "-enclave", enclave,
                                 "-out", f"/tmp/sgx_sign_out-{port}", "-resign"],
                                env={"WINELOADERNOEXEC": "1", "DISPLAY": ":0", "WINEPREFIX": wineprefix},
                                stdout=1, stderr=1)
    # while True:
    #     try:
    #         sgx_sign.wait(1)
    #         raise OSError
    #     except subprocess.TimeoutExpired:
    #         pass
    #     try:
    #         s = socket.socket()
    #         s.settimeout(1)
    #         s.connect(("127.0.0.1", port))
    #         s.recv(1)
    #         s.close()
    #         break
    #     except ConnectionRefusedError as ex:
    #         print(ex)
    #     except socket.timeout as ex:
    #         print(ex)
    # exit()

    gdb = GdbController()
    gdb.write = lambda *args: GdbController.write(gdb, *args, timeout_sec=60)

    events = deque()
    events.extend(gdb.write(f"target remote localhost:{port}"))
    # events.extend(gdb.write("-exec-continue"))
    events.extend(gdb.write("-break-insert *0x140009200"))
    if dump_range:
        events.extend(gdb.write(f"-break-condition 1 $r9>=0x{dump_range.start:x}"))
    # events.extend(gdb.write("-break-list"))
    events.extend(gdb.write("-exec-continue"))

    offset = -1
    page_data = {}
    page_flags = {}
    progress = tqdm.tqdm(total=total_size, unit_scale=True, unit='B', unit_divisor=1024, leave=True)
    while True:
        if not events:
            events.extend(gdb.get_gdb_response(timeout_sec=30))

        e: dict = events.popleft()
        message: str = e['message']
        payload: dict = e.get('payload')

        if e.get('token'):
            token = e['token']
            if 'memory' in payload:
                assert len(payload['memory']) == 1
                data = b16decode(payload['memory'][0]['contents'], True)

            if token == 9 and 'value' in payload:  # r9
                offset = int(payload['value'])
                if dump_range and offset not in dump_range:
                    events.extend(gdb.write("-exec-exit"))
                    break
                continue
            elif token == 8:
                if 'value' in payload:  # r8
                    data = bytes(0x1000)
                elif message == "error":
                    pass  # ignore
                else:
                    assert 'memory' in payload  # *r8 == page_data
                page_data[offset] = data
                progress.n = offset
                progress.update(len(data))
                progress.set_postfix_str(f"Offset: 0x{offset:x}")
            elif token == 11:  # sinfo
                flags = int.from_bytes(data[:8], "little", signed=False)
                page_flags[offset] = flags
            else:
                print(f"Error: Unknown Token ({token})")
                exit(1)
            continue

        if message == "":
            pass
        elif message == "done":
            pass
            # pprint(e)
        elif message == "stopped":
            reason = payload.get('reason')
            if reason == "breakpoint-hit":
                addr = int(payload['frame']['addr'], 16)
                if addr == 0x140009200:
                    events.extend(gdb.write("9-data-evaluate-expression $r9"))
                    events.extend(gdb.write(f"8-data-evaluate-expression $r8"))
                    events.extend(gdb.write(f"8-data-read-memory-bytes $r8 {0x1000}"))
                    events.extend(gdb.write(f"11-data-read-memory-bytes *(void**)($rsp+0x28) {64}"))
                    events.extend(gdb.write("-exec-continue"))
                else:
                    assert False, "Unknown breakpoint"
            else:
                print(f"Stopped: {reason}")
                if reason == 'exited-normally':
                    break
        elif message == "error":
            print(payload["msg"])
            exit(1)
        else:
            pass
            # print(message)

    progress.close()

    try:
        sgx_sign.wait(5)
    except subprocess.TimeoutExpired:
        sgx_sign.kill()

    return page_flags, page_data


def main(enclave: str, out_dir: str, sgx_sign_exe: str):
    sgx_sign_exe = Path(sgx_sign_exe).absolute().as_posix()

    with open(sgx_sign_exe, "rb") as f:
        sgx_sign_hash = hashlib.sha3_256(f.read()).hexdigest()
        if sgx_sign_hash != "34baa711a9b9444d2d9b29ba977c5e433231241e9edb44833b6e042392a9c60f":
            assert False, f"Incompatible {sgx_sign_exe} ({sgx_sign_hash})"

    try:
        wineprefix = "/tmp/sgxdumpwine/"
        Path(wineprefix).mkdir(exist_ok=True)
        msg = subprocess.check_output(["wine64", sgx_sign_exe, "gendata",
                                       "-enclave", enclave,
                                       "-out", "/tmp/sgx_sign_out", "-resign"],
                                      env={"DISPLAY": ":0", "WINEPREFIX": wineprefix},
                                      stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError as ex:
        print(ex.output.decode())
        raise
    msg = re.search(r"^The required memory is (0x[0-9a-f]+)\.\s+Succeed.\s+$", msg, re.M)
    assert msg
    total_size = int(msg.group(1), 16)
    assert total_size

    # pool = ThreadPoolExecutor(max_workers=30)
    # jobs = []
    # chunk_size = 0x10_000
    # for i in range(0, total_size, chunk_size):
    #     jobs.append(pool.submit(dump_pages, enclave, out_dir, sgx_sign_exe, dump_range=range(i, i + chunk_size)))
    # else:
    #     jobs.append(pool.submit(dump_pages, enclave, out_dir, sgx_sign_exe, dump_range=range(total_size // chunk_size * chunk_size, 1 << 64)))
    # pool.shutdown(wait=True, cancel_futures=False)

    page_flags, page_data = dump_pages(enclave, out_dir, sgx_sign_exe, total_size=total_size)

    out_base = Path(out_dir).joinpath(Path(enclave).name)

    with open(f"{out_base}.mem.log", "w") as f, open(f"{out_base}.tcs.txt", "w") as tcs:
        for off, flags in page_flags.items():
            f.write(f"{hex(off)}: {hex(flags)}\n")
            if flags == 0x100:
                tcs.write(hex(off) + "\n")

    with open(f"{out_base}.mem", "wb") as f:
        for off, data in page_data.items():
            f.seek(off, 0)
            f.write(data)

    modes = []
    for addr, flags in sorted(page_flags.items()):
        perm = flags & 0xff
        page_type = (flags >> 8) & 0xff
        l = len(page_data[addr])
        if modes and modes[-1][0] + modes[-1][1] == addr and modes[-1][2] == perm and modes[-1][3] == page_type:
            modes[-1][1] += l
        else:
            modes.append([addr, l, perm, page_type])

    with open(f"{out_base}.layout", "wb") as f:
        for addr, size, perm, t in modes:
            f.write(struct.pack("<QQbb", addr, size, perm, t))
        else:
            f.write(struct.pack("<QQbb", 0, 0, 0, 0))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage {sys.argv[0]} <enclave.signed.dll>")
        exit(1)

    enclave = Path(sys.argv[1])
    assert enclave.exists()

    main(enclave.as_posix(), enclave.parent.as_posix(), Path(__file__).parent.joinpath("sgx_sign.exe").as_posix())
