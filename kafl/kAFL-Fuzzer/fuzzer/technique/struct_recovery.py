import itertools

try:
    from fuzzer.technique.helper import rand
except ImportError:
    rand = None


class SpecialField:
    @staticmethod
    def getType():
        raise NotImplementedError

    def getSizeInParent(self):
        raise NotImplementedError

    @staticmethod
    def parse(data):
        raise NotImplementedError

    def serialize_gen(self):
        raise NotImplementedError


class SizeofField(SpecialField):
    def __init__(self, buffer_offset):
        self.buffer_offset = buffer_offset

    @staticmethod
    def getType():
        return "S"

    def getSizeInParent(self):
        return 8

    @staticmethod
    def parse(data):
        return SizeofField(int(data.pop(0)))

    def serialize_gen(self):
        yield self.buffer_offset


class StrlenField(SpecialField):
    def __init__(self, buffer_offset):
        self.buffer_offset = buffer_offset

    @staticmethod
    def getType():
        return "L"

    def getSizeInParent(self):
        return 8

    @staticmethod
    def parse(data):
        return StrlenField(int(data.pop(0)))

    def serialize_gen(self):
        yield self.buffer_offset


class InputNode:
    PAGE_SIZE = 0x1000
    MASK = ~(-1 << 47 | 0xff)

    def __init__(self, parent=None):
        self.address = 0
        self.size = 0
        self.childs: dict[int, InputNode] = {}
        self.fields: dict[int, SpecialField] = {}
        self.data = bytearray()
        self.parent: InputNode = parent
        self.type = "C"

    def getSizeInParent(self):
        return 8

    def getType(self):
        return self.type

    def set_size(self, new_size):
        self.size = new_size
        del self.data[new_size:]
        self.data.extend(rand.bytes(new_size - len(self.data)))

    def increase_guard_page(self, fault):
        if self.type.islower():
            return False
        if self.is_in_guard_page(fault):
            self.size += max(4, min(4, fault - self.address - self.size))
            if len(self.data) < self.size:
                self.data.extend(rand.bytes(self.size - len(self.data)))
            else:
                del self.data[self.size:]
            return self

        for off, in_c in self.childs.items():
            altered_page = in_c.increase_guard_page(fault)
            if altered_page:
                return altered_page
        return False

    def is_in_guard_page(self, fault):
        # print(f"{self.address + self.size - 7:x} <= {fault:x} < {self.address + self.size + self.PAGE_SIZE:x}")
        return self.address + self.size - 15 <= fault < self.address + self.size + self.PAGE_SIZE

    def get_payload_size(self):
        return (
                self.size
                - 8 * len(self.childs)
                + sum(c.get_payload_size() for c in self.childs.values())
                - sum(s.getSizeInParent() for s in self.fields.values())
        )

    def _make_ptr_get_data(self):
        return self.data + b"".join(c._make_ptr_get_data() for c in self.childs.values())

    def make_ptr_from_data(self, fault, debug: list = None):
        if fault < 0x100:  # don't fix nullptr
            if debug is not None:
                debug.extend([[], []])
            return False

        data = self._make_ptr_get_data()
        found_equal = []
        found_similar = []
        for i in range(0, len(data) - 7):
            payload_int = int.from_bytes(data[i:i + 8], "little")
            if fault == payload_int:
                found_equal.append(i)
            elif fault >= 0x1000 and 0 <= fault - payload_int < 0x100:
                found_similar.append(i)

        if debug is not None:
            debug.append(found_equal)
            debug.append(found_similar)

        if found_equal:
            if len(found_equal) == 1:
                fix_idx = found_equal[0]
            else:
                print("MAKE PTR: Double found equal", hex(fault))
                return False
        elif found_similar:
            if len(found_similar) == 1:
                fix_idx = found_similar[0]
            else:
                print("MAKE PTR: Double found similar", hex(fault))
                return False
        else:
            return False

        success, _ = self._make_ptr_at_global_data_offset(fix_idx)
        return success

    def _make_ptr_at_global_data_offset(self, offset):
        if offset < self.size:
            for i in range(max(0, offset - self.getSizeInParent() + 1), offset + self.getSizeInParent()):
                if i in self.childs or i in self.fields:  # TODO Adjust for differently sized fields
                    print("MAKE PTR: Overlapping ptr found")
                    return False, offset
            self.childs[offset] = InputNode(self)
            self.childs = dict(sorted(self.childs.items()))
            return True, offset
        offset -= self.size
        for child in self.childs.values():
            success, offset = child._make_ptr_at_global_data_offset(offset)
            if success is not None or offset < 0:
                return success, offset
        return None, offset

    def make_field(self, off, field):
        self.fields[off] = field
        self.fields = dict(sorted(self.fields.items()))

    def fill_with_data(self, data):
        data_size = self.size - sum(s.getSizeInParent() for s in itertools.chain(self.childs.values(), self.fields.values()))
        self.data = bytearray(data[:data_size])
        remaining = data[data_size:]

        for off, sub in sorted(itertools.chain(self.childs.items(), self.fields.items())):
            self.data[off:off] = bytes(sub.getSizeInParent())

        for off, child in self.childs.items():
            remaining = child.fill_with_data(remaining)
        return remaining

    def get_payload_gen(self):
        data = self.data.copy()
        for off, f in sorted(list(self.childs.items()) + list(self.fields.items()), reverse=True):
            del data[off:off + f.getSizeInParent()]
        yield data
        for off, child in self.childs.items():
            yield from child.get_payload_gen()

    def get_payload(self):
        return b"".join(self.get_payload_gen())

    @staticmethod
    def parse_serialized_struct(data: bytes):
        if isinstance(data, bytes):
            data = data.split()

        inp = InputNode()

        size = data.pop(0)
        try:
            size, addr = size.split(b":")
        except ValueError:
            addr = "0"
        inp.size = int(size)
        inp.address = int(addr, 16)

        for i in range(int(data.pop(0))):
            field = data.pop(0)
            ty = field[0:1]
            idx = int(field[1:])
            if ty in b'CIiPpZz':
                # noinspection PyTypeChecker
                inp.childs[idx] = InputNode.parse_serialized_struct(data)
                inp.childs[idx].type = ty.decode()
                inp.childs[idx].parent = inp
            elif ty in b'S':
                inp.fields[idx] = SizeofField.parse(data)
            elif ty in b'L':
                inp.fields[idx] = StrlenField.parse(data)
            else:
                raise ValueError
        return inp

    def serialize_gen(self):
        yield self.size
        yield len(self.childs) + len(self.fields)
        for off, child in self.childs.items():
            yield child.getType() + str(off)
            yield from child.serialize_gen()
        for off, field in self.fields.items():
            yield field.getType() + str(off)
            yield from field.serialize_gen()

    def serialize(self):
        return " ".join(map(str, self.serialize_gen())).encode() + b" "

    def show(self, file=None):
        if self.address:
            print(f"0x{self.address:08x}:", file=file)

        def _show(self, indent):
            self.data = self.data.ljust(self.size, b"\0")
            skip = 0
            if not self.size:
                print(" " * indent + "<empty>", end="", file=file)
            for i in range(self.size):
                if skip > 0:
                    skip -= 1
                    continue

                if i % 8 == 0:
                    if i > 0:
                        print(file=file)
                    print(" " * indent + f"{i:04x}: ", end="", file=file)
                elif i % 4 == 0:
                    print(" ", end="", file=file)

                c = self.childs.get(i)
                f = self.fields.get(i)
                if c is not None:
                    if self.address:
                        print(f"0x{self.address:08x}:", file=file)
                    else:
                        print(f"nullptr:", file=file)
                    _show(c, indent + 4)
                    skip += 7
                elif f is not None:
                    print(f"{f.__class__.__name__}<{f.buffer_offset}>", end="", file=file)
                    skip += f.getSizeInParent() - 1
                else:
                    print(f"{self.data[i]:02x} ", end="", file=file)

        _show(self, 0)
        print(file=file)

    def __repr__(self):
        return f"[0x{self.address:x}, {self.size}, {self.data}, {self.childs}]"

    def mutate_struct(self, fault):
        return bool(self.increase_guard_page(fault) or self.make_ptr_from_data(fault))


def benchmark():
    import timeit

    def time(stmt, setup="pass"):
        timer = timeit.Timer(stmt, setup=setup, globals=globals())
        number = timer.autorange()[0]
        timings = timer.repeat(10, number=number)
        # print([t / number for t in timings])
        print(f"Min: {min(timings) / number * 1_000_000:>6.2f}µs, Max: {max(timings) / number * 1_000_000:>6.2f}µs\t{stmt}")
        return sorted(timings)[len(timings) // 2] / number

    print("Sum: {:>6.2f}µs".format(
        (time("n = InputNode.parse_serialized_struct(b'32:1 2 16 16:2 1 8 12:3 0 24 16:4 0 ')")
         + time("n.fill_with_data(bytes(100))", setup="n = InputNode.parse_serialized_struct(b'32:1 2 16 16:2 1 8 12:3 0 24 16:4 0 ')")
         # + time("n.get_payload()", setup="n = InputNode.parse_serialized_struct(b'32:1 2 16 16:2 1 8 12:3 0 24 16:4 0 '); n.fill_with_data(bytes(100))")
         + time("n.mutate_struct(0x7ffff7fa5ffc)", setup="n = InputNode.parse_serialized_struct(b'32:1 2 16 16:2 1 8 12:3 0 24 16:4 0 '); n.fill_with_data(bytes(100))")
         ) * 1_000_000
    ))


if __name__ == '__main__':
    from base64 import b16decode

    n = InputNode.parse_serialized_struct(b"40:0x7ffff7faafd8 3 C8 4:0x7ffff7fa8ffc 0 C24 4:0x7ffff7fa6ffc 0 S16 8")
    print(n.serialize())

    n.fill_with_data(bytes(range(256)))
    n.show()

    # benchmark()
