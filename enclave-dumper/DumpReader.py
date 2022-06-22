import argparse
import struct
from base64 import b16decode
from dataclasses import dataclass
from enum import Enum
from typing import Dict

__all__ = [
    "DumpPage",
    "DumpReader",
]

PAGE_SIZE = 0x1000


def hex_to_bytes(h: str) -> bytes:
    return b16decode(h, casefold=True)


def hex_to_int(h):
    return int(h, 16)


class CommandsEnum(Enum):
    ENCLAVE_MOD_RANGE = "enclave_mod_range"
    ENCLAVE_INIT = "enclave_init"
    ENCLAVE_ADD_PAGE = "enclave_add_page"
    ENCLAVE_CREATE = "enclave_create"


@dataclass
class DumpPage:
    addr: int
    perm: int
    data: bytes
    page_type: int

    def __repr__(self):
        return f"{self.__class__.__name__} (addr={self.addr:#08x}, perm={self.perm:#03b}, data=<len({len(self.data)})>)"


class DumpReader:
    def __init__(self, file):
        self.file = file

        self.commands = []
        self.pages: Dict[int, DumpPage] = {}
        self.secs_addr: int = -1

        self._parse_dump()
        self._build_pages()

    def _parse_dump(self):
        with open(self.file, "r") as f:
            fi = iter(f)
            for ln in fi:
                assert ln[:5] == "SGX: "

                ln_split = ln.split()
                if ln_split[1] == CommandsEnum.ENCLAVE_CREATE.value:
                    self.commands.append((CommandsEnum.ENCLAVE_CREATE, ln_split[4]))
                elif ln_split[1] == CommandsEnum.ENCLAVE_ADD_PAGE.value:
                    target_addr = ln_split[2]
                    mrmask = ln_split[3]
                    sec_info = next(fi).split()[1]
                    page_data = next(fi).split()[1]
                    self.commands.append((CommandsEnum.ENCLAVE_ADD_PAGE, {"target_addr": target_addr, "mrmask": mrmask, "sec_info": sec_info, "page_data": page_data}))
                elif ln_split[1] == CommandsEnum.ENCLAVE_INIT.value:
                    encl_addr = ln_split[2]
                    sigstruct = ln_split[4]
                    einittoken = ln_split[6]
                    self.commands.append((CommandsEnum.ENCLAVE_INIT, {"encl_addr": encl_addr, "sigstruct": sigstruct, "einittoken": einittoken}))
                elif ln_split[1] == CommandsEnum.ENCLAVE_MOD_RANGE.value:
                    self.commands.append((CommandsEnum.ENCLAVE_MOD_RANGE, {"addr": ln_split[2], "nr_pages": ln_split[3], "flags": ln_split[4]}))
                else:
                    assert False, ln

    def _build_pages(self):
        TCS = []
        for c, args in self.commands:
            if c == CommandsEnum.ENCLAVE_ADD_PAGE:
                addr = hex_to_int(args["target_addr"])
                assert addr not in self.pages
                if args["sec_info"][:4] == "0001":  # TCS
                    TCS.append(addr)
                page = DumpPage(addr, hex_to_int(args["sec_info"][:2]), hex_to_bytes(args["page_data"]), hex_to_int(args["sec_info"][2:4]))
                self.pages[addr] = page
            elif c == CommandsEnum.ENCLAVE_INIT:
                self.secs_addr = hex_to_int(args["encl_addr"])
            elif c == CommandsEnum.ENCLAVE_MOD_RANGE:
                addr = hex_to_int(args["addr"])
                for i in range(hex_to_int(args["nr_pages"])):
                    perm = hex_to_int(args["flags"][0])
                    try:
                        self.pages[addr + i * PAGE_SIZE].perm = perm
                    except KeyError:
                        self.pages[addr + i * PAGE_SIZE] = DumpPage(addr + i * PAGE_SIZE, perm, b'', None)

        for tcs in TCS:
            print(f"{tcs - min(self.pages):#x}")

    def __repr__(self):
        return f"{self.__class__.__name__} (addr={self.secs_addr:#08x}, pages=\n{chr(10).join(hex(k) + ': ' + str(v) for k, v in self.pages.items())})"


def convert(enclave_dump_file):
    reader = DumpReader(enclave_dump_file)

    min_page = min(reader.pages)
    max_page = max(reader.pages)

    size = max_page - min_page + len(reader.pages[max_page].data)
    if size > 100 * 2 ** 20:
        print(f"WARNING: Enclave size: {size / 2 ** 20:.2f} MB")

    memory = bytearray(size)

    for page in reader.pages.values():
        memory[page.addr - min_page:page.addr - min_page + len(page.data)] = page.data

    with open(f"{enclave_dump_file}.mem", "wb") as f:
        f.write(memory)

    modes = []
    for page in sorted(reader.pages.values(), key=lambda p: p.addr):
        if modes and modes[-1][0] + modes[-1][1] == page.addr and modes[-1][2] == page.perm and modes[-1][3] == page.page_type:
            modes[-1][1] += len(page.data)
        else:
            modes.append([page.addr, len(page.data), page.perm, page.page_type])

    with open(f"{enclave_dump_file}.layout", "wb") as f:
        for addr, size, perm, t in modes:
            f.write(struct.pack("<QQbb", addr - min_page, size, perm, t))
        else:
            f.write(struct.pack("<QQbb", 0, 0, 0, 0))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Convert a textual enclave dump to a binary memory dump")
    parser.add_argument("src", help="Textual enclave dump")
    # parser.add_argument("layout", nargs='?', help="Destination of binary layout")

    args = parser.parse_args()
    src = args.src

    convert(src)
