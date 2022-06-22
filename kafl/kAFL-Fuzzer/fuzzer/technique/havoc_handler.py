# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style havoc mutations (havoc stage)
"""

import logging

from common.util import read_binary_file, find_diffs
from fuzzer.technique.helper import *

def insert_word(data, chars, term):
    if len(data) < 2:
        return data

    offset = rand.int(len(data))
    if rand.int(2) > 1:
        replen = 0  # plain insert
    else:
        replen = rand.int(len(data) - offset)

    word_length = min(len(data) - offset, rand.int(10) + 1)

    body = ''.join([term] + [rand.select(chars) for _ in range(word_length - 1)] + [term])
    return b''.join([data[:offset], body.encode(), data[offset+replen:]])


def havoc_insert_line(data):
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
    num = "0123456789.,x"
    special = "!\"$%&/()=?`'#+*+-_,.;:\\{[]}<>"
    terminator = ["\n", " ", "\0", '""', "'", "", " ADF\n"]
    return insert_word(data, rand.select([alpha, num, special]), rand.select(terminator))


def havoc_perform_bit_flip(data, area):
    if len(data) < 1:
        return

    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-1, pos))
    bit = rand.int(8)
    #pos = bit//8

    data[pos] ^= (0x80 >> (bit % 8))


def havoc_perform_insert_interesting_value_8(data, area):
    if len(data) < 1:
        return

    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-1, pos))
    value = rand.select(interesting_8_Bit)

    data[pos:pos] = value.to_bytes(1, 'little', signed=True)


def havoc_perform_insert_interesting_value_16(data, area):
    if len(data) < 2:
        return

    order = rand.select(("big", "little"))
    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-2, pos))
    value = rand.select(interesting_16_Bit)

    data[pos:pos+2] = value.to_bytes(2, order, signed=True)


def havoc_perform_insert_interesting_value_32(data, area):
    if len(data) < 4:
        return

    order = rand.select(("big", "little"))
    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-4, pos))
    value = rand.select(interesting_32_Bit)

    data[pos:pos+4] = value.to_bytes(4, order, signed=True)


def havoc_perform_byte_subtraction_8(data, area):
    if len(data) < 1:
        return

    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-1, pos))
    value = int.from_bytes(data[pos:pos+1], 'little', signed=False)
    value = (value - 1 - rand.int(AFL_ARITH_MAX)) % 0xff

    data[pos:pos] = value.to_bytes(1, 'little', signed=False)


def havoc_perform_byte_addition_8(data, area):
    if len(data) < 1:
        return

    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-1, pos))
    value = int.from_bytes(data[pos:pos+1], 'little', signed=False)
    value = (value + 1 + rand.int(AFL_ARITH_MAX)) % 0xff

    data[pos:pos] = value.to_bytes(1, 'little', signed=False)


def havoc_perform_byte_subtraction_16(data, area):
    if len(data) < 2:
        return

    order = rand.select(("big", "little"))
    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-2, pos))
    value = int.from_bytes(data[pos:pos+2], order, signed=False)
    value = (value - 1 - rand.int(AFL_ARITH_MAX)) % 0xffff

    data[pos:pos+2] = value.to_bytes(2, order, signed=False)


def havoc_perform_byte_addition_16(data, area):
    if len(data) < 2:
        return

    order = rand.select(("big", "little"))
    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-2, pos))
    value = int.from_bytes(data[pos:pos+2], order, signed=False)
    value = (value + 1 + rand.int(AFL_ARITH_MAX)) % 0xffff

    data[pos:pos+2] = value.to_bytes(2, order, signed=False)


def havoc_perform_byte_subtraction_32(data, area):
    if len(data) < 4:
        return

    order = rand.select(("big", "little"))
    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-4, pos))
    value = int.from_bytes(data[pos:pos+4], order, signed=False)
    value = (value - 1 - rand.int(AFL_ARITH_MAX)) % 0xffffffff

    data[pos:pos+4] = value.to_bytes(4, order, signed=False)


def havoc_perform_byte_addition_32(data, area):
    if len(data) < 4:
        return data

    order = rand.select(("big", "little"))
    pos = area + rand.int(16)-8
    pos = max(0,min(len(data)-4, pos))
    value = int.from_bytes(data[pos:pos+4], order, signed=False)
    value = (value + 1 + rand.int(AFL_ARITH_MAX)) % 0xffffffff

    data[pos:pos+4] = value.to_bytes(4, order, signed=False)

def havoc_perform_set_random_byte_value(data, area):
    if len(data) < 1:
        return

    pos = area + rand.int(16)-8
    pos = max(0, min(len(data)-1, pos))

    data[pos] ^= (1 + rand.int(255))


def havoc_perform_delete_random_byte(data, area):
    if len(data) < 2:
        return

    del_length = AFL_choose_block_len(len(data) - 1)

    maxpos = len(data) - del_length
    pos = area + rand.int(16)-8
    pos = max(0,min(maxpos, pos))

    del_from = pos
    data[del_from:del_from+del_length] = data[del_from + del_length:]
    # TODO broken
    #return data[:del_from] + data[del_from + del_length:]
    #return b''.join([data[:del_from] + data[del_from + del_length:]])


def havoc_perform_clone_random_byte(data, area):
    data_len = len(data)

    if data_len < 1 or data_len + HAVOC_BLK_XL >= KAFL_MAX_FILE:
        return

    # clone bytes with p=3/4, else insert block of constant bytes
    if rand.int(4):
        clone_len = AFL_choose_block_len(data_len)
        clone_from = rand.int(data_len - clone_len + 1)
        body = data[clone_from: clone_from + clone_len]
    else:
        clone_len = AFL_choose_block_len(HAVOC_BLK_XL)
        val = rand.int(256) if rand.int(2) else rand.select(data)
        body = clone_len * val.to_bytes(1, 'little', signed=False)

    clone_to = rand.int(data_len)
    # TODO not in-place
    #return data[:clone_to] + body + data[clone_to:]

def havoc_perform_byte_seq_override(data, area):

    if len(data) < 2:
        return 

    copy_len = AFL_choose_block_len(len(data) - 1)
    copy_from = rand.int(len(data) - copy_len + 1)
    copy_to = rand.int(len(data) - copy_len + 1)

    body = b''

    if rand.int(4):
        if copy_from != copy_to:
            body = data[copy_from: copy_from + copy_len]
    else:
        if rand.int(2):
            value = rand.int(256)
        else:
            value = rand.select(data)
        body = copy_len * value.to_bytes(1, 'little', signed=False)

    data[copy_to:copy_to+copy_len] = body
    #return data
    #return data[:copy_to] + body + data[copy_to+copy_len:]


def havoc_perform_byte_seq_extra1(data):
    pass


def havoc_perform_byte_seq_extra2(data):
    pass


def havoc_splicing_gen(data, files, max_rounds):
    if len(data) < 2 or files is None:
        return data

    file_limit = min(64, len(files))
    max_rounds = max(1, max_rounds//file_limit)
    for file in rand.sample(files, file_limit):
        file_data = read_binary_file(file)
        if len(file_data) < 2:
            continue

        first_diff, last_diff = find_diffs(data, file_data)
        if last_diff < 2 or first_diff == last_diff:
            continue

        #split_location = first_diff + rand.int(last_diff - first_diff)
        #yield data[:split_location] + file_data[split_location:]
        split_samples = min(max_rounds,(last_diff-first_diff)//10)
        for split_location in rand.sample(range(last_diff-first_diff), split_samples):
            yield data[:split_location] + file_data[split_location:]

    # none of the files are suitable
    #return None

def havoc_splice_file(data, filename):
    if len(data) < 2 or filename is None:
        return None

    file_data = read_binary_file(filename)
    if len(file_data) < 2:
        return None

    first_diff, last_diff = find_diffs(data, file_data)
    if last_diff < 2 or first_diff == last_diff:
        return None

    split_location = first_diff + rand.int(last_diff - first_diff)
    return data[:split_location] + file_data[split_location:]


dict_set = set()
dict_import = []

redqueen_dict = {}
redqueen_addr_list = []
redqueen_known_addrs = set()
redqueen_seen_addr_to_value = {}


def set_dict(new_dict):
    global dict_import
    dict_import = new_dict
    dict_set = set(new_dict)


def clear_redqueen_dict():
    global redqueen_dict, redqueen_addr_list
    logging.info("clearing dict %s" % repr(redqueen_dict))
    redqueen_dict = {}
    redqueen_addr_list = []


def get_redqueen_dict():
    global redqueen_dict
    return redqueen_dict


def get_redqueen_seen_addr_to_value():
    global redqueen_seen_addr_to_value
    return redqueen_seen_addr_to_value


def add_to_redqueen_dict(addr, val):
    global redqueen_dict, redqueen_addr_list

    assert len(redqueen_dict) == len(redqueen_addr_list)

    val = val[:16]
    for v in val.split(b'0'):
        if len(v) > 3:
            if not addr in redqueen_dict:
                redqueen_dict[addr] = set()
                redqueen_addr_list.append(addr)
            redqueen_dict[addr].add(v)


def append_handler(handler):
    global havoc_handler
    havoc_handler.append(handler)


# placing dict entry at variable offset overlapping the end should also be useful?
def dict_insert_sequence(data, entry, entry_pos=None):
    if entry_pos is None:
        entry_pos = rand.int(max([0, len(data) - len(entry)]))
    return b''.join([data[:entry_pos], entry, data[entry_pos+len(entry):]])

def dict_replace_sequence(data, entry, entry_pos=None):
    if entry_pos is None:
        entry_pos = rand.int(max([0, len(data) - len(entry)]))
    return b''.join([data[:entry_pos], entry, data[entry_pos:]])

def havoc_dict_insert(data, area):
    global redqueen_dict
    global dict_import

    has_redq = len(redqueen_dict) > 0
    has_dict = len(dict_import) > 0
    coin = rand.int(2)

    if not has_dict and has_redq and coin:
        addr = rand.select(redqueen_addr_list)
        dict_values = list(redqueen_dict[addr])
        dict_entry = rand.select(dict_values)
        return dict_insert_sequence(data, dict_entry)

    elif has_dict:
        dict_entry = rand.select(dict_import)
        #dict_entry = dict_entry[:len(data)]
        return dict_insert_sequence(data, dict_entry)
    return data

def havoc_dict_replace(data, area):
    global redqueen_dict
    global dict_import

    has_redq = len(redqueen_dict) > 0
    has_dict = len(dict_import) > 0
    coin = rand.int(2)

    if not has_dict and has_redq and coin:
        addr = rand.select(redqueen_addr_list)
        dict_values = list(redqueen_dict[addr])
        dict_entry = rand.select(dict_values)
        return dict_replace_sequence(data, dict_entry)

    elif has_dict:
        dict_entry = rand.select(dict_import)
        #dict_entry = dict_entry[:len(data)]
        return dict_replace_sequence(data, dict_entry)
    return data



havoc_handler = [havoc_perform_bit_flip,
                 havoc_perform_bit_flip,
                 havoc_perform_bit_flip,
                 havoc_perform_bit_flip,
                 havoc_perform_insert_interesting_value_8,
                 havoc_perform_insert_interesting_value_16,
                 #havoc_perform_insert_interesting_value_32,
                 havoc_perform_byte_subtraction_8,
                 havoc_perform_byte_addition_8,
                 havoc_perform_byte_subtraction_16,
                 havoc_perform_byte_addition_16,
                 #havoc_perform_byte_subtraction_32,
                 #havoc_perform_byte_addition_32,
                 havoc_perform_set_random_byte_value,
                 havoc_perform_set_random_byte_value,
                 havoc_perform_set_random_byte_value,
                 #havoc_perform_delete_random_byte,
                 #havoc_perform_clone_random_byte,
                 #havoc_perform_byte_seq_override,
                 # dict mutators are initialized in havoc_init()
                 #havoc_dict_insert,
                 #havoc_dict_replace,

                 # havoc_perform_byte_seq_extra1,
                 # havoc_perform_byte_seq_extra2,
                 # havoc_insert_line,
                 ]
