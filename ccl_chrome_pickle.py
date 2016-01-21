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
import datetime
import io
from enum import Enum

__contact__ = "Alex Caithness"
__version__ = "0.4.1"
__description__ = "A reimplementation of the Google PickleIterator"
__outputtype__ = 1
__outputext__ = None


class PickleType(Enum):
    Bool = 1
    Int16 = 2
    UInt16 = 3
    Int32 = 4
    UInt32 = 5
    Int64 = 6
    UInt64 = 7
    Single = 8
    Double = 9
    Blob = 10
    String = 11
    String16 = 12
    DateTime = 13
    Pickle = 14
    String16ByteCount = 15


class PickleReader:
    def __init__(self, blob):
        self._stream = io.BytesIO(blob)
        try:
            self.pickle_length = self._read_int32()
        except struct.error as e:
            raise EOFError("End of stream when reading pickle length", )
        if len(blob) - 4 != self.pickle_length:
            raise ValueError("Declared pickle length not equal to blob length")

        self.current = None
        self.length = len(blob)
        
    def _read_int16(self):
        x = self._stream.read(4)
        return struct.unpack("<h", x[0:2])[0]

    def _read_int32(self):
        x = self._stream.read(4)
        return struct.unpack("<i", x)[0]

    def _read_int64(self):
        x = self._stream.read(8)
        return struct.unpack("<q", x)[0]

    def _read_uint16(self):
        x = self._stream.read(4)
        return struct.unpack("<H", x[0:2])[0]

    def _read_uint32(self):
        x = self._stream.read(4)
        return struct.unpack("<I", x)[0]

    def _read_uint64(self):
        x = self._stream.read(8)
        return struct.unpack("<Q", x)[0]

    def _read_single(self):
        x = self._stream.read(4)
        return struct.unpack("<f", x)[0]

    def _read_double(self):
        x = self._stream.read(8)
        return struct.unpack("<d", x)[0]

    def _read_raw(self, length):
        # NB will always align the buffer after the read
        start = self._stream.tell()
        blob = self._stream.read(length)
        if len(blob) < length:
            raise EOFError(
                   "End of file reached when reading {0} bytes from offset {1} in the pickle")

        alignment = (4 - (length % 4)) if length % 4 != 0 else 0
        
        self._stream.seek(alignment, 1)

        return blob

    def read_short(self):
        try:
            self.current = self._read_int16()
        except struct.error:
            self.current = None
            return False
        return True

    def read_int(self):
        try:
            self.current = self._read_int32()
        except struct.error:
            self.current = None
            return False
        return True

    def read_long(self):
        try:
            self.current = self._read_int64()
        except struct.error:
            self.current = None
            return False
        return True

    def read_ushort(self):
        try:
            self.current = self._read_uint16()
        except struct.error:
            self.current = None
            return False
        return True

    def read_uint(self):
        try:
            self.current = self._read_uint32()
        except struct.error:
            self.current = None
            return False
        return True

    def read_ulong(self):
        try:
            self.current = self._read_uint64()
        except struct.error:
            self.current = None
            return False
        return True

    def read_bool(self):
        try:
            self.current = self._read_int32() != 0
        except struct.error:
            self.current = None
            return False
        return True

    def read_single(self):
        try:
            self.current = self._read_single()
        except struct.error:
            self.current = None
            return False
        return True

    def read_double(self):
        try:
            self.current = self._read_double()
        except struct.error:
            self.current = None
            return False
        return True

    def read_timestamp(self):
        try:
            x = self._read_int64()
        except struct.error:
            self.current = None
            return False

        self.current = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=x)
        return True

    def read_blob(self, is_doubled_length=False):
        try:
            length = self._read_int32()
        except struct.error:
            self.current = None
            return False
        
        if length == -1:
            self.current = None
            return True

        try:
            self.current = self._read_raw(length * (2 if is_doubled_length else 1))
        except EOFError:
            self.current = None
            return False

        return True

    def read_str(self):
        success = self.read_blob()
        if success and self.current is not None:
            self.current = self.current.decode("utf-8")

        return success
        
    def read_str16_with_byte_count(self):
        success = self.read_blob(is_doubled_length=False)
        if success and self.current is not None:
            self.current = self.current.decode("utf-16-le")

        return success

    def read_str16_with_char_count(self):
        success = self.read_blob(is_doubled_length=True)
        if success and self.current is not None:
            self.current = self.current.decode("utf-16-le")

        return success

    def read_pickle(self):
        length_buff = self._stream.read(4)
        if len(length_buff) != 4:
            self.current = None
            return False

        length, = struct.unpack("<i", length_buff)
        pickle_buff = self._stream.read(length)

        if len(pickle_buff) != length:
            self.current = None
            return False

        self.current = PickleReader(length_buff + pickle_buff)
        return True

    def deserialise_into_dict(self, fields, raise_on_missing=False):
        """
        fields: an iterable of tuples (attribute_name, pickle_type)
        """

        result = {}

        for field, field_type in fields:
            if not isinstance(field, str):
                raise TypeError("field must be str")
            if not isinstance(field_type, PickleType):
                raise TypeError("field_type must be a PickleType")

            success = _func_lookup[field_type](self)
            if not success and raise_on_missing:
                raise ValueError("Field: {0} couldn't be read.")

            if field not in result or success:
                result[field] = self.current

        return result

    def iter_deserialise(self, fields, raise_on_missing=False):
        """
        fields: an iterable of pickle_types
        """

        for field_type in fields:
            if not isinstance(field_type, PickleType):
                raise TypeError("field_type must be a PickleType")

            if not _func_lookup[field_type](self) and raise_on_missing:
                raise ValueError("Field: {0} couldn't be read.".format(field_type))

            yield self.current


_func_lookup = {PickleType.Bool: PickleReader.read_bool,
                PickleType.Int16: PickleReader.read_short,
                PickleType.UInt16: PickleReader.read_ushort,
                PickleType.Int32: PickleReader.read_int,
                PickleType.UInt32: PickleReader.read_uint,
                PickleType.Int64: PickleReader.read_long,
                PickleType.UInt64: PickleReader.read_ulong,
                PickleType.Single: PickleReader.read_single,
                PickleType.Double: PickleReader.read_double,
                PickleType.Blob: PickleReader.read_blob,
                PickleType.String: PickleReader.read_str,
                PickleType.String16: PickleReader.read_str16_with_char_count,
                PickleType.DateTime: PickleReader.read_timestamp,
                PickleType.Pickle: PickleReader.read_pickle,
                PickleType.String16ByteCount: PickleReader.read_str16_with_byte_count}
