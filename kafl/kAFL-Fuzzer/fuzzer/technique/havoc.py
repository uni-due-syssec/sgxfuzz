# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style havoc and splicing stage 
"""

import glob

from common.config import FuzzerConfiguration
from fuzzer.technique.havoc_handler import *


def load_dict(file_name):
    f = open(file_name)
    dict_entries = []
    for line in f:
        if not line.startswith("#"):
            try:
                dict_entries.append(line.split('="')[1].split('"\n')[0])
            except:
                pass
    f.close()
    return dict_entries


def init_havoc(config):
    global location_corpus
    if config.argument_values["dict"]:
        raise NotImplementedError
        set_dict(load_dict(FuzzerConfiguration().argument_values["dict"]))
    # AFL havoc adds these at runtime as soon as available dicts are non-empty
    if config.argument_values["dict"] or config.argument_values["redqueen"]:
        append_handler(havoc_dict_insert)
        append_handler(havoc_dict_replace)

    location_corpus = config.argument_values['work_dir'] + "/corpus/"


def havoc_range(perf_score):
    max_iterations = int(perf_score//6)

    if max_iterations < AFL_HAVOC_MIN:
        max_iterations = AFL_HAVOC_MIN

    #if max_iterations > AFL_HAVOC_MAX:
    #    max_iterations = AFL_HAVOC_MAX

    return max_iterations


# havoc could use focusing around offsets
# iterate through payload for focused havoc, then expand scope
def mutate_seq_havoc_array(payload, func, max_iterations, resize=False):
    if resize:
        payload = payload + payload

    while max_iterations > 0:
        #stacking = rand.int(AFL_HAVOC_STACK_POW2)
        #stacking = 1 << (stacking)
        stacking = 1 << 6
        max_iterations -= stacking
        data = bytearray(payload)
        area = rand.int(len(data))
        for _ in range(stacking):
            handler = rand.select(havoc_handler)
            #data = handler(data, area)[:KAFL_MAX_FILE]
            handler(data, area)
            func(data)

def mutate_seq_damage_byte(payload, func, max_iterations, resize=False):
    if resize:
        payload = payload + payload

    while max_iterations > 0:
        #stacking = rand.int(AFL_HAVOC_STACK_POW2)
        #stacking = 1 << (stacking)
        stacking = 1 << 7
        max_iterations -= stacking
        data = bytearray(payload)
        for _ in range(stacking):
            area = rand.int(len(data))
            havoc_perform_set_random_byte_value(data, area)
            func(data)

def mutate_seq_damage_bit(payload, func, max_iterations, resize=False):
    if resize:
        payload = payload + payload

    while max_iterations > 0:
        #stacking = rand.int(AFL_HAVOC_STACK_POW2)
        #stacking = 1 << (stacking)
        stacking = 1 << 7
        max_iterations -= stacking
        data = bytearray(payload)
        for _ in range(stacking):
            havoc_perform_set_random_byte_value(data, rand.int(len(data)))
            havoc_perform_set_random_byte_value(data, rand.int(len(data)))
            havoc_perform_set_random_byte_value(data, rand.int(len(data)))
            havoc_perform_set_random_byte_value(data, rand.int(len(data)))
            havoc_perform_set_random_byte_value(data, rand.int(len(data)))
            func(data)

# splicing much more effective than havoc
# but can run out of inputs (low execs)
# could expand on diff finder to generate more options
def mutate_seq_splice_array(data, func, max_iterations, resize=False):
    global location_corpus
    # depending on overall desired max_iterations, do a small amount of
    # splices and a good amount of havoc rounds for each splice 
    splice_rounds = 1 + max_iterations//(AFL_HAVOC_MAX//2)
    havoc_rounds = max_iterations//splice_rounds

    #files = glob.glob(location_corpus + "/regular/payload_*")
    path = location_corpus + "/regular/"
    files = os.listdir(path)
    for _ in range(splice_rounds):
        f = rand.select(files)
        spliced_data = havoc_splice_file(data, path+f)
        if spliced_data is None:
            print("abort splice")
            continue
        func(spliced_data)
        mutate_seq_damage_byte(spliced_data,
                               func,
                               havoc_rounds//2,
                               resize=resize)
        mutate_seq_havoc_array(spliced_data,
                               func,
                               havoc_rounds//2,
                               resize=resize)

def mutate_seq_splice_many(data, func, max_iterations, resize=False):
    global location_corpus
    files = glob.glob(location_corpus + "/regular/payload_*")
    splice_rounds = 64
    havoc_rounds = max_iterations//splice_rounds
    #print("splice: %d * %d = %d executions" % (splice_rounds, havoc_rounds, max_iterations))
    for spliced_data in havoc_splicing_gen(data, files, splice_rounds):
        func(spliced_data)
        mutate_seq_damage_byte(spliced_data,
                               func,
                               havoc_rounds,
                               resize=resize)
    return
