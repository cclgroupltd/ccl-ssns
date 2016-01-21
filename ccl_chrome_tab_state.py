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

import struct
import typing
import ccl_chrome_pickle

__contact__ = "Alex Caithness"
__version__ = "0.3.1"
__description__ = "Reimplementation of classes in Chrome related to Tab and Session management"
__outputtype__ = 1
__outputext__ = None

IS_ANDROID = True

class ChromeTransition:
    _core_mask = 0xff
    _qualifier_mask = 0xffffff00
    _core_transitions = {
            0 : "Link",
            1 : "Typed",
            2 : "AutoBookmark",
            3 : "AutoSubframe",
            4 : "ManualSubframe",
            5 : "Generated",
            6 : "AutoToplevel",
            7 : "FormSubmit",
            8 : "Reload",
            9 : "Keyword",
            10 :"KeywordGenerated"
    }
    _qualifiers = {
            0x00800000 : "Blocked",
            0x01000000 : "ForwardBack",
            0x02000000 : "FromAddressBar",
            0x04000000 : "HomePage",
            0x08000000 : "FromApi",
            0x10000000 : "ChainStart",
            0x20000000 : "ChainEnd",
            0x40000000 : "ClientRedirect",
            0x80000000 : "ServerRedirect"
    }

    def __init__(self, value):
        self.value = value
        if value < 0:
            # as far as python is concerned, this converts from signed to unsigned
            value += (0x80000000 * 2)
        self.core_transition = ChromeTransition._core_transitions[value & ChromeTransition._core_mask]
        self.qualifiers = []
        for flag in ChromeTransition._qualifiers:
            if (value & ChromeTransition._qualifier_mask) & flag > 0:
                self.qualifiers.append(ChromeTransition._qualifiers[flag])

    def __str__(self):
        return "; ".join([self.core_transition] + self.qualifiers)

    def __repr__(self):
        return "ChromeTransition ({0}): {1})".format(self.value, str(self))


def read_string_vector_from_page_state_pickle(pickle_reader):
    if not pickle_reader.read_int():
        raise EOFError
    count = pickle_reader.current

    result = []
    for i in range(count):
        if not pickle_reader.read_str16_with_byte_count():
            raise EOFError

        result.append(pickle_reader.current)

    return result


def read_double_from_page_state_pickle(pickle_reader):
    # Seriously, why is this done this way in the format?
    pickle_reader.read_blob()
    assert len(pickle_reader.current) == 8
    return struct.unpack("<d", pickle_reader.current)[0]


class HttpBody:
    def __init__(self, body_data, file_ranges, blobs, identifier, contains_passwords):
        self.body_data = body_data
        self.file_ranges = file_ranges
        self.blobs = blobs
        self.identifier = identifier
        self.contains_passwords = contains_passwords
        self.content_type = None

    @classmethod
    def from_pickle(cls, pickle_reader, version):
        pickle_reader.read_bool()  # HttpBody is present
        if not pickle_reader.current:
            return None

        http_body_data = []
        http_file_ranges = []
        http_blobs = []

        pickle_reader.read_int()
        element_count = pickle_reader.current

        for i in range(element_count):
            pickle_reader.read_int()
            body_type = pickle_reader.current

            if body_type == 0:  # blink::WebHTTPBody::Element::TypeData
                if pickle_reader.read_blob() and pickle_reader.current:
                    http_body_data.append(pickle_reader.current)
            elif body_type == 1 or body_type == 3:
                # blink::WebHTTPBody::Element::TypeFile or FileSystemUrl
                if body_type == 1:
                    pickle_reader.read_str16_with_byte_count()
                else:
                    pickle_reader.read_str()
                file_path = pickle_reader.current
                pickle_reader.read_long()
                file_start = pickle_reader.current
                pickle_reader.read_long()
                file_length = pickle_reader.current
                file_modification_time = read_double_from_page_state_pickle(pickle_reader)
                http_file_ranges.append((file_path, file_start,
                                         file_length, file_modification_time))
            elif body_type == 2:  # blink::WebHTTPBody::Element::Blob
                pickle_reader.read_str()
                if version >= 16:
                    http_blobs.append(pickle_reader.current)

            else:
                raise ValueError("Invalid WebHTTPBody::Element::Element type")

        pickle_reader.read_long()
        identifier = pickle_reader.current
        if version >= 12:
            pickle_reader.read_bool()
            contains_passwords = pickle_reader.current
        else:
            contains_passwords = True

        return cls(http_body_data, http_file_ranges, http_blobs, identifier, contains_passwords)


class FrameState:
    def __init__(self, version, url_string, target, scroll_offset, referrer, document_state,
                 page_scale_factor, item_sequence_number, document_sequence_number,
                 referrer_policy, pinch_viewport_scroll_offset, scroll_restoration_type,
                 state_object, http_body, child_states=[]):
        self.version = version
        self.url_string = url_string
        self.target = target
        self.scroll_offset = scroll_offset
        self.referrer = referrer
        self.document_state = document_state
        self.page_scale_factor = page_scale_factor
        self.item_sequence_number = item_sequence_number
        self.document_sequence_number = document_sequence_number
        self.referrer_policy = referrer_policy
        self.pinch_viewport_scroll_offset = pinch_viewport_scroll_offset
        self.scroll_restoration_type = scroll_restoration_type
        self.state_object = state_object
        self.http_body = http_body
        self.child_states = child_states

    @classmethod
    def from_pickle(cls, pickle_reader, version, is_top):
        if version < 14 and not is_top:
            pickle_reader.read_int()  # skip redundant field

        pickle_reader.read_str16_with_byte_count()
        url_string = pickle_reader.current

        if version < 19:
            pickle_reader.read_str16_with_byte_count()  # skip redundant field

        pickle_reader.read_str16_with_byte_count()
        target = pickle_reader.current

        if version < 15:
            pickle_reader.read_str16_with_byte_count()  # skip redundant field
            pickle_reader.read_str16_with_byte_count()  # skip redundant field
            pickle_reader.read_str16_with_byte_count()  # skip redundant field
            read_double_from_page_state_pickle(pickle_reader) # skip redundant field

        pickle_reader.read_int()
        x = pickle_reader.current
        pickle_reader.read_int()
        y = pickle_reader.current

        scroll_offset = x, y

        if version < 15:
            pickle_reader.read_bool()
            pickle_reader.read_int()

        pickle_reader.read_str16_with_byte_count()
        referrer = pickle_reader.current

        document_state = read_string_vector_from_page_state_pickle(pickle_reader)

        page_scale_factor = read_double_from_page_state_pickle(pickle_reader)
        pickle_reader.read_long()
        item_sequence_number = pickle_reader.current
        pickle_reader.read_long()
        document_sequence_number = pickle_reader.current

        if version >= 21 and version < 23:
            pickle_reader.read_long()  # skip redundant field

        if version >= 17 and version < 19:
            pickle_reader.read_long()  # skip redundant field

        referrer_policy = 0
        if version >= 18:
            pickle_reader.read_int()
            referrer_policy = pickle_reader.current
        else:
            referrer_policy = -1

        if version >= 20:
            x = read_double_from_page_state_pickle(pickle_reader)
            y = read_double_from_page_state_pickle(pickle_reader)

            pinch_viewport_scroll_offset = x, y
        else:
            pinch_viewport_scroll_offset = -1, -1

        if version >= 22:
            pickle_reader.read_int()
            scroll_restoration_type = pickle_reader.current
        else:
            scroll_restoration_type = -1

        pickle_reader.read_bool()  # has state object

        if pickle_reader.current:
            pickle_reader.read_str16_with_byte_count()
            state_object = pickle_reader.current
        else:
            state_object = None

        http_body = HttpBody.from_pickle(pickle_reader, version)
        pickle_reader.read_str16_with_byte_count()
        if http_body is not None:
            http_body.content_type = pickle_reader.current

        if version < 14:
            pickle_reader.read_str16_with_byte_count()  # skip redundant field

        if IS_ANDROID and version == 11:
            read_double_from_page_state_pickle(pickle_reader)  # skip redundant field
            pickle_reader.read_bool()  # skip redundant field

        pickle_reader.read_int()
        child_count = pickle_reader.current
        children_states = []

        for i in range(child_count):
            children_states.append(FrameState.from_pickle(pickle_reader, version, False))

        return cls(version, url_string, target, scroll_offset, referrer, document_state,
                   page_scale_factor, item_sequence_number, document_sequence_number,
                   referrer_policy, pinch_viewport_scroll_offset, scroll_restoration_type,
                   state_object, http_body, children_states)


class PageState:
    MIN_VERSION = 11
    CURRENT_VERSION = 23

    def __init__(self, version, referenced_files, frame_state, url):
        self.version = version
        self.referenced_files = referenced_files
        self.frame_state = frame_state
        self.url = url

    @classmethod
    def from_pickle(cls, pickle_reader):
        if not pickle_reader.read_int():
            raise EOFError
        version = pickle_reader.current

        if version == -1:
            pickle_reader.read_str()
            return cls(None, None, None, pickle_reader.current)

        if version > cls.CURRENT_VERSION or version < cls.MIN_VERSION:
            raise ValueError("invalid PageState Version")

        referenced_files = []
        if version >= 14:
            referenced_files = read_string_vector_from_page_state_pickle(pickle_reader)

        frame_state = FrameState.from_pickle(pickle_reader, version, True)

        return cls(version, referenced_files, frame_state, None)


class NavigationEntry:
    def __init__(self, index=None, url=None, title=None, page_state_blob=None,
                 transition_type=None, type_mask=None, referrer_url=None,
                 referrer_policy=None, original_request_url=None,
                 is_overriding_user_agent=False, timestamp=None, search_terms=None,
                 http_status_code=0, **kwargs):
        self.index = index
        self.url = url
        self.title = title
        if page_state_blob:
            page_state_pickle = ccl_chrome_pickle.PickleReader(page_state_blob)
            self.page_state = PageState.from_pickle(page_state_pickle)
        else:
            self.page_state = None
        self.transition_type = ChromeTransition(transition_type)
        self.type_mask = type_mask
        self.referrer_url = referrer_url
        self.referrer_policy = referrer_policy
        self.original_request_url = original_request_url
        self.is_overriding_user_agent = is_overriding_user_agent
        self.timestamp = timestamp
        self.search_terms = search_terms
        self.http_status_code = http_status_code

    @classmethod
    def from_pickle(cls, pickle_reader):
        fields = (("index", ccl_chrome_pickle.PickleType.Int32),
                  ("url", ccl_chrome_pickle.PickleType.String),
                  ("title", ccl_chrome_pickle.PickleType.String16),
                  ("page_state_blob", ccl_chrome_pickle.PickleType.Blob),
                  ("transition_type", ccl_chrome_pickle.PickleType.Int32),
                  ("type_mask", ccl_chrome_pickle.PickleType.Int32),
                  ("referrer_url", ccl_chrome_pickle.PickleType.String),
                  ("referrer_policy", ccl_chrome_pickle.PickleType.Int32),
                  ("original_request_url", ccl_chrome_pickle.PickleType.String),
                  ("is_overriding_user_agent", ccl_chrome_pickle.PickleType.Bool),
                  ("timestamp", ccl_chrome_pickle.PickleType.DateTime),
                  ("search_terms", ccl_chrome_pickle.PickleType.String16),
                  ("http_status_code", ccl_chrome_pickle.PickleType.Int32),
                  ("referrer_policy", ccl_chrome_pickle.PickleType.Int32))

        return cls(**pickle_reader.deserialise_into_dict(fields))


class TabState:
    def __init__(self, is_incognito, current_entry_index,
                 navigation_entries: typing.Sequence[NavigationEntry]=()):
        self.is_incognito = is_incognito
        self.current_entry_index = current_entry_index
        self.navigation_entries = navigation_entries

    @classmethod
    def from_pickle(cls, pickle_reader):
        fields_types = (ccl_chrome_pickle.PickleType.Bool,
                        ccl_chrome_pickle.PickleType.Int32,
                        ccl_chrome_pickle.PickleType.Int32)

        fields = pickle_reader.iter_deserialise(fields_types, True)
        is_incognito, entry_count, current_entry_index = tuple(fields)

        navigation_entries = []
        for entry_index in range(entry_count):
            if not pickle_reader.read_int():
                raise ValueError()

            navigation_blob_length = pickle_reader.current  # not that it matters...

            if not pickle_reader.read_pickle():
                raise ValueError()

            navigation_pickle = pickle_reader.current
            navigation_entries.append(NavigationEntry.from_pickle(navigation_pickle))

        return cls(is_incognito, current_entry_index, navigation_entries)
