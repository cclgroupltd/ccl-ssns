#!/usr/bin/env python3

"""
Copyright (c) 2016, CCL Forensics
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the CCL Forensics nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CCL FORENSICS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import sys
import os
import io
import struct
import binascii
import csv

import ccl_chrome_pickle
import ccl_chrome_tab_state

__contact__ = "Alex Caithness"
__version__ = "0.2.0"
__description__ = "Parses Chrome (desktop) SNSS Files (Last, Current Tabs, Sessions"
__outputtype__ = 1
__outputext__ = None


DATE_FMT = "%d/%m/%Y %H:%M:%S"


class SsnsError(Exception):
    pass


def read_tab_restore_command(stream):
    pickle = ccl_chrome_pickle.PickleReader(stream.read())
    pickle.read_int()
    tab_id = pickle.current

    return tab_id, ccl_chrome_tab_state.NavigationEntry.from_pickle(pickle)


def read_navigation_command(stream):
    size_bytes = stream.read(2)
    if len(size_bytes) < 2:
        return None  # we've hit the end of the file
    command_size, = struct.unpack("<H", size_bytes)
    command_bytes = stream.read(command_size)
    if len(command_bytes) < command_size:
        raise SsnsError("Error: Command bytes is less than the stated command size. "
                        "We have hit the end of the stream prematurely")

    command_buffer = io.BytesIO(command_bytes)

    command_id = command_buffer.read(1)[0]
    if command_id in (1, 6):
        return True, read_tab_restore_command(command_buffer)
    else:
        return False, None


def iter_navigation_commands(stream):
    while True:
        result = read_navigation_command(stream)
        if result is None:
            break
        elif result[0]:
            yield result[1]


def flatten_frame_states(frame_state: ccl_chrome_tab_state.FrameState):
    yield frame_state
    for child in frame_state.child_states:
        yield from flatten_frame_states(child)


def parse_blink_form_state(obj):
    if len(obj) < 1:
        raise ValueError("Too short to be Blink serialized form state version")

    magic = obj[0]

    if magic != "\n\r?% Blink serialized form state version 9 \n\r=&":
        raise ValueError("Not a Blink serialized form state version 9")

    reader = iter(obj[1:])
    result = {}
    while True:
        try:
            form_key = reader.__next__()
        except StopIteration:
            break

        result.setdefault(form_key, {})
        item_count = int(reader.__next__())

        for j in range(item_count):
            field_name = reader.__next__()
            field_type = reader.__next__()
            result[form_key].setdefault((field_name, field_type), [])
            values = result[form_key][(field_name, field_type)]
            field_count = int(reader.__next__())
            for k in range(field_count):
                values.append(reader.__next__())

    return result


def main(args):
    in_path = args[0]
    out_path = args[1]

    os.mkdir(out_path)

    f = open(in_path, "rb")
    header = f.read(8)
    magic, version = struct.unpack("<4si", header)
    if magic != b"SNSS":
        print("ERROR: Invalid header (expected:SNSS (0x534e5353); actual: {0})".format(
            binascii.hexlify(magic).decode()))
        exit(1)
    if version != 1:
        print("ERROR: Invalid version (expected: 1; actual: {0}".format(version))

    tab_tables = {}
    file_objects = []

    for tab_id, navigation in iter_navigation_commands(f):
        if tab_id not in tab_tables:
            tab_file = open(os.path.join(out_path, "tab{0}.csv".format(tab_id)), "wt",
                            encoding="utf-8", newline="")
            file_objects.append(tab_file)
            tab_tables[tab_id] = csv.writer(tab_file)
            tab_tables[tab_id].writerow(["Index", "Title", "URL", "Timestamp",
                                         "Transition Type", "Referrer",
                                         "Search Terms", "HTTP Status Code",
                                         "Page State"])

        has_frame_state = False
        if navigation.page_state:
            for frame in flatten_frame_states(navigation.page_state.frame_state):
                if frame.document_state:
                    has_frame_state = True
                    form_state = parse_blink_form_state(frame.document_state)
                    page_state_file = open(
                            os.path.join(
                                    out_path,
                                    "tab{0}-navigation{1} page_state.csv".format(
                                            tab_id, navigation.index)),
                            "wt", encoding="utf-8", newline="")
                    page_state_writer = csv.writer(page_state_file)
                    page_state_writer.writerow(["Form ID", "Key", "Type", "Value"])

                    for form_id in form_state:
                        for (key, form_type), value in form_state[form_id].items():
                            page_state_writer.writerow([form_id, key, form_type, value])

                    page_state_file.close()

        tab_tables[tab_id].writerow([navigation.index, navigation.title, navigation.url,
                                     navigation.timestamp.strftime(DATE_FMT),
                                     navigation.transition_type, navigation.referrer_url,
                                     navigation.search_terms, navigation.http_status_code,
                                     "yes" if has_frame_state else "no"])

    for file in file_objects:
        file.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: {0} <SNSS File (Current/Last Tabs/Session> <out dir>".format(
            os.path.basename(sys.argv[0])))
        exit(1)

    main(sys.argv[1:])
	
