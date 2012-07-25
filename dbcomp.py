#!/usr/bin/env python

from __future__ import print_function
import sys
import os
import zlib
import binascii
import sqlite3
from struct import Struct

# File format of .sbstore files:
#
# We do not store the add prefixes, those are retrieved by
# decompressing the PrefixSet cache whenever we need to apply
# an update.
#
# byte slicing: Many of the 4-byte values stored here are strongly
# correlated in the upper bytes, and uncorrelated in the lower
# bytes. Because zlib/DEFLATE requires match lengths of at least
# 3 to achieve good compression, and we don't get those if only
# the upper 16-bits are correlated, it is worthwhile to slice 32-bit
# values into 4 1-byte slices and compress the slices individually.
# The slices corresponding to MSBs will compress very well, and the
# slice corresponding to LSB almost nothing. Because of this, we
# only apply DEFLATE to the 3 most significant bytes, and store the
# LSB uncompressed.
#
# byte sliced (numValues) data format:
#    uint32 compressed-size
#    compressed-size bytes    zlib DEFLATE data
#        0...numValues        byte MSB of 4-byte numValues data
#    uint32 compressed-size
#    compressed-size bytes    zlib DEFLATE data
#        0...numValues        byte 2nd byte of 4-byte numValues data
#    uint32 compressed-size
#    compressed-size bytes    zlib DEFLATE data
#        0...numValues        byte 3rd byte of 4-byte numValues data
#    0...numValues            byte LSB of 4-byte numValues data
#
# Store data format:
#    uint32 magic
#    uint32 version
#    uint32 numAddChunks
#    uint32 numSubChunks
#    uint32 numAddPrefixes
#    uint32 numSubPrefixes
#    uint32 numAddCompletes
#    uint32 numSubCompletes
#    0...numAddChunks               uint32 addChunk
#    0...numSubChunks               uint32 subChunk
#    byte sliced (numAddPrefixes)   uint32 add chunk of AddPrefixes
#    byte sliced (numSubPrefixes)   uint32 sub chunk of SubPrefixes
#    byte sliced (numSubPrefixes)   uint32 add chunk of SubPrefixes
#    byte sliced (numSubPrefixes)   uint32 SubPrefixes
#    0...numAddCompletes            32-byte Completions
#    0...numSubCompletes            32-byte Completions
#    16-byte MD5 of all preceding data

class SBHash:
    def __init__(self, prefix=None, addc=None, delc=None):
        self.prefix = prefix
        self.addchunk = addc
        self.subchunk = delc

class SBData:
    def __init__(self):
        # XXX: are sets usable for these 2?
        self.addchunks = []
        self.subchunks = []
        self.addprefixes = []
        self.subprefixes = []
        self.addcompletes = []
        self.subcompletes = []
    def addchunk(self, chunk):
        self.addchunks.append(chunk)
    def subchunk(self, chunk):
        self.subchunks.append(chunk)

def read_unzip(fp, comp_size):
    """Read comp_size bytes from a zlib stream and
     return as a tuple of bytes"""
    zlib_data = fp.read(comp_size)
    uncomp_data = zlib.decompress(zlib_data)
    bytebuffer = Struct("=" + str(len(uncomp_data)) + "B")
    data = bytebuffer.unpack_from(uncomp_data, 0)
    return data

def read_raw(fp, size):
    """Read raw bytes from a stream and return as a tuple of bytes"""
    bytebuffer = Struct("=" + str(size) + "B")
    data = bytebuffer.unpack_from(fp.read(size), 0)
    return data

def readuint32(fp):
    uint32 = Struct("=I")
    return uint32.unpack_from(fp.read(uint32.size), 0)[0]

def read_bytesliced(fp, count):
    comp_size = readuint32(fp)
    slice1 = read_unzip(fp, comp_size)
    comp_size = readuint32(fp)
    slice2 = read_unzip(fp, comp_size)
    comp_size = readuint32(fp)
    slice3 = read_unzip(fp, comp_size)
    slice4 = read_raw(fp, count)

    if (len(slice1) != len(slice2)) or \
       (len(slice2) != len(slice3)) or \
       (len(slice3) != len(slice4)):
        print("Slices inconsistent %d %d %d %d" % (len(slice1), len(slice2),
                                                   len(slice3), len(slice4)))
        exit(1)

    result = []
    for i in range(count):
        val = (slice1[i] << 24) | (slice2[i] << 16) \
            | (slice3[i] << 8) | slice4[i]
        result.append(val)
    return result

def read_sbstore(sbstorefile):
    data = SBData()
    fp = open(sbstorefile, "rb")

    # parse header
    header = Struct("=IIIIIIII")
    magic, version, num_add_chunk, num_sub_chunk, \
    num_add_prefix, num_sub_prefix, \
    num_add_complete, num_sub_complete = header.unpack_from(fp.read(header.size), 0)
    print(("Magic %X Version %u NumAddChunk: %d NumSubChunk: %d "
           + "NumAddPrefix: %d NumSubPrefix: %d NumAddComplete: %d "
           + "NumSubComplete: %d") % (magic, version, num_add_chunk,
                                      num_sub_chunk, num_add_prefix,
                                      num_sub_prefix, num_add_complete,
                                      num_sub_complete))

    # parse chunk data
    for x in range(num_add_chunk):
        chunk = readuint32(fp)
        data.addchunk(chunk)
    for x in range(num_sub_chunk):
        chunk = readuint32(fp)
        data.subchunk(chunk)

    # read bytesliced data
    addprefix_addchunk = read_bytesliced(fp, num_add_prefix)
    subprefix_subchunk = read_bytesliced(fp, num_sub_prefix)
    subprefix_addchunk = read_bytesliced(fp, num_sub_prefix)
    subprefixes = read_bytesliced(fp, num_sub_prefix)

    # Construct the prefix objects
    for x in range(num_add_prefix):
        prefix = SBHash(0, addprefix_addchunk[x])
        data.addprefixes.append(prefix)
    for x in range(num_sub_prefix):
        prefix = SBHash(subprefixes[x], subprefix_addchunk[x],
                        subprefix_subchunk[x])
        data.subprefixes.append(prefix)
    for x in range(num_add_complete):
        complete = read_raw(fp, 32)
        addchunk = readuint32(fp)
        entry = SBHash(complete, addchunk)
        data.addcompletes.append(entry)
    for x in range(num_sub_complete):
        complete = read_raw(fp, 32)
        addchunk = readuint32(fp)
        subchunk = readuint32(fp)
        entry = SBHash(complete, addchunk, subchunk)
        data.subcompletes.append(entry)
    md5sum = fp.read(16)
    print("MD5: " + binascii.b2a_hex(md5sum))
    # EOF detection
    dummy = fp.read(1)
    if len(dummy) or (len(md5sum) != 16):
        if len(md5sum) != 16:
            print("Checksum truncated")
        print("File doesn't end where expected:", end=" ")
        # Don't count the dummy read, we finished before it
        ourpos = fp.tell() - len(dummy)
        # Seek to end
        fp.seek(0, 2)
        endpos = fp.tell()
        print("%d bytes remaining" % (endpos - ourpos))
        exit(1)

def parse_new_databases(dir):
    # look for all sbstore files
    sb_lists = []
    for file in os.listdir(dir):
        if file.endswith(".sbstore"):
            sb_file = os.path.join(dir, file)
            sb_name = file[:-len(".sbstore")]
            print("Reading " + sb_name)
            sb_data = read_sbstore(sb_file)
            sb_lists.append((sb_name, sb_file, sb_data))
            print("\n")
    print("Found safebrowsing lists:")
    for name, file, data in sb_lists:
        print(name)

def main(argv):
    new_profile_dir = argv.pop()
    old_profile_dir = argv.pop()
    new_data = parse_new_databases(new_profile_dir)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Need to specify 2 profile directories.")
        exit(1)
    main(sys.argv)
