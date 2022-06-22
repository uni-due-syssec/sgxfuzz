# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later
import codecs
import logging
import os
import sys

class FileFormatter(logging.Formatter):
    def __init__(self):
        super().__init__(fmt="%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)s] %(msg)s")        

class StreamFormatter(logging.Formatter):
    def __init__(self):
        super().__init__(fmt="%(levelname)s \u001b[34;1m%(name)s\u001b[0m [%(filename)s:%(lineno)s] %(msg)s")

    def format(self, record):
        format_orig = self._style._fmt

        format_prefix = ""
        if record.levelno == logging.INFO:
            format_prefix = "INFO\t"
        elif record.levelno == logging.DEBUG:
            format_prefix = "\u001b[94mDBG\u001b[0m\t"
        elif record.levelno == logging.WARNING:
            format_prefix = "\u001b[0;33mWARN\u001b[0m\t"
        elif record.levelno == logging.ERROR:
            format_prefix = "\u001b[91mERR\u001b[0m\t"
        elif record.levelno == logging.CRITICAL:
            format_prefix = "\u001b[1m\u001b[31mCRTCL\u001b[0m\t"

        self._style._fmt = format_prefix + "[%(filename)s:%(lineno)s] %(msg)s"

        fmt = logging.Formatter.format(self, record)
        self._style._fmt = format_orig

        return fmt

def init_logger(log_file_path, log_level=logging.INFO):
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(log_level)
    stream_formatter = StreamFormatter()
    stream_handler.setFormatter(stream_formatter)

    if not os.path.exists(log_file_path):
        os.makedirs(log_file_path)

    file_handler = logging.FileHandler(log_file_path + "/debug.log", mode="w+")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = FileFormatter()
    file_handler.setFormatter(file_formatter)

    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[
            stream_handler,
            file_handler
        ]
    )
