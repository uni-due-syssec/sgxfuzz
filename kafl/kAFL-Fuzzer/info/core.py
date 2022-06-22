# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import os
import time

from common.log import init_logger
from common.qemu import qemu
from common.self_check import post_self_check
from common.util import prepare_working_dir

def start(config):

    work_dir = config.argument_values["work_dir"]
    if config.argument_values['v'] or config.argument_values["debug"]:
        init_logger(work_dir, logging.DEBUG)
    else:
        init_logger(work_dir)

    if not post_self_check(config):
        return -1

    if not prepare_working_dir(config):
        logging.error("Refuse to operate on existing work directory. Use --purge to override.")
        return 1

    logging.info("Dumping target addresses...")

    # TODO: use proper temp file or store to $work_dir
    if os.path.exists("/tmp/kAFL_info.txt"):
        os.remove("/tmp/kAFL_info.txt")

    q = qemu(0, config)
    q.start()
    q.shutdown()

    try:
        with open("/tmp/kAFL_info.txt", 'r') as f:
            print(f.read())
        #os.remove("/tmp/kAFL_info.txt")
    except:
        pass

    return 0
