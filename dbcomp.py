#!/usr/bin/env python

from __future__ import print_function
import sys
import os
import zlib
import binascii
import operator
import sqlite3
import struct

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
        self.name = None
        self.addchunks = set()
        self.subchunks = set()
        self.addprefixes = []
        self.subprefixes = []
        self.addcompletes = []
        self.subcompletes = []
    def add_addchunk(self, chunk):
        self.addchunks.add(chunk)
    def add_subchunk(self, chunk):
        self.subchunks.add(chunk)
    def fill_addprefixes(self, prefixes):
        """Add prefixes are stored in the PrefixSet instead of in the sbstore,
        so allow filling them in seperately afterwards."""
        assert len(prefixes) == len(self.addprefixes), \
               "Prefixes: %d AddPrefixes: %d" \
               % (len(prefixes), len(self.addprefixes))
        for i, pref in enumerate(self.addprefixes):
            pref.prefix = prefixes[i]
    def sort_all_data(self):
        self.addprefixes.sort(
            key=operator.attrgetter('prefix', 'addchunk'))
        self.subprefixes.sort(
            key=operator.attrgetter('prefix', 'subchunk', 'addchunk'))
        self.addcompletes.sort(
            key=operator.attrgetter('prefix', 'addchunk'))
        self.subcompletes.sort(
            key=operator.attrgetter('prefix', 'subchunk', 'addchunk'))

def read_unzip(fp, comp_size):
    """Read comp_size bytes from a zlib stream and
     return as a tuple of bytes"""
    zlib_data = fp.read(comp_size)
    uncomp_data = zlib.decompress(zlib_data)
    bytebuffer = struct.Struct("=" + str(len(uncomp_data)) + "B")
    data = bytebuffer.unpack_from(uncomp_data, 0)
    return data

def read_raw(fp, size):
    """Read raw bytes from a stream and return as a tuple of bytes"""
    bytebuffer = struct.Struct("=" + str(size) + "B")
    data = bytebuffer.unpack_from(fp.read(size), 0)
    return data

def readuint32(fp):
    uint32 = struct.Struct("=I")
    return uint32.unpack_from(fp.read(uint32.size), 0)[0]

def readuint16(fp):
    uint16 = struct.Struct("=H")
    return uint16.unpack_from(fp.read(uint16.size), 0)[0]

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
    header = struct.Struct("=IIIIIIII")
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
        data.add_addchunk(chunk)
    for x in range(num_sub_chunk):
        chunk = readuint32(fp)
        data.add_subchunk(chunk)

    # read bytesliced data
    addprefix_addchunk = read_bytesliced(fp, num_add_prefix)
    subprefix_subchunk = read_bytesliced(fp, num_sub_prefix)
    subprefix_addchunk = read_bytesliced(fp, num_sub_prefix)
    subprefixes = read_bytesliced(fp, num_sub_prefix)

    # Construct the prefix objects
    for i in range(num_add_prefix):
        prefix = SBHash(0, addprefix_addchunk[i])
        data.addprefixes.append(prefix)
    for i in range(num_sub_prefix):
        prefix = SBHash(subprefixes[i], subprefix_addchunk[i],
                        subprefix_subchunk[i])
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
    return data

def pset_to_prefixes(index_prefixes, index_starts, index_deltas):
    prefixes = []
    prefix_len = len(index_prefixes)
    for i in range(prefix_len):
        prefix = index_prefixes[i]
        prefixes.append(prefix)
        start = index_starts[i]
        if i != (prefix_len - 1):
            end = index_starts[i + 1]
        else:
            end = len(index_deltas)
        #print("s: %d e: %d" % (start, end))
        for j in range(start, end):
            #print("%d " % index_deltas[j])
            prefix += index_deltas[j]
            prefixes.append(prefix)
    return prefixes

def read_pset(filename):
    fp = open(filename, "rb")
    version = readuint32(fp)
    indexsize = readuint32(fp)
    deltasize = readuint32(fp)
    print("Version: %X Indexes: %d Deltas: %d" % (version, indexsize, deltasize))
    index_prefixes = []
    index_starts = []
    index_deltas = []
    for x in range(indexsize):
        index_prefixes.append(readuint32(fp))
    for x in range(indexsize):
        index_starts.append(readuint32(fp))
    for x in range(deltasize):
        index_deltas.append(readuint16(fp))
    prefixes = pset_to_prefixes(index_prefixes, index_starts, index_deltas)
    # empty set has a special form
    if len(prefixes) and prefixes[0] == 0:
        prefixes = []
    return prefixes

def parse_new_databases(dir):
    # look for all sbstore files
    sb_lists = {}
    for file in os.listdir(dir):
        if file.endswith(".sbstore"):
            sb_file = os.path.join(dir, file)
            sb_name = file[:-len(".sbstore")]
            print("Reading " + sb_name)
            sb_data = read_sbstore(sb_file)
            prefixes = read_pset(os.path.join(dir, sb_name + ".pset"))
            sb_data.name = sb_name
            sb_data.fill_addprefixes(prefixes)
            sb_data.sort_all_data()
            sb_lists[sb_name] = sb_data
            print("\n")
    print("Found safebrowsing lists in new DB:")
    for name in sb_lists.keys():
        print(name)
    return sb_lists

def parse_old_database(dir):
    filename = os.path.join(dir, "urlclassifier3.sqlite")
    connection = sqlite3.connect(filename)
    cursor = connection.cursor()
    tables_query = "SELECT name, id FROM moz_tables"
    cursor.execute(tables_query)
    sb_names = {}
    while True:
        row = cursor.fetchone()
        if not row: break
        name, id = row[0], row[1]
        sb_names[name] = id
    cursor.close()
    print("\nFound safebrowsing lists in old DB:")
    for key in sb_names.keys():
        print(key)
    sb_lists = {}
    for table_name in sb_names.keys():
        table_id = sb_names[table_name]
        data = SBData()
        data.name = table_name

        # Gather add prefixes
        addpref_query = ("SELECT domain, partial_data, chunk_id "
                         "FROM moz_classifier WHERE table_id = ?")
        cursor = connection.cursor()
        cursor.execute(addpref_query, (table_id,))
        while True:
            row = cursor.fetchone()
            if not row: break
            domain, prefix, addchunk = row[0], row[1], row[2]
            if not prefix:
                prefix = struct.unpack("=I", domain)[0]
            else:
                prefix = struct.unpack("=I", prefix)[0]
            pref_data = SBHash(prefix, addchunk)
            data.addprefixes.append(pref_data)
            data.add_addchunk(addchunk)
        cursor.close()

        # Gather sub prefixes
        subpref_query = ("SELECT domain, partial_data, chunk_id, "
                         "add_chunk_id FROM moz_subs WHERE table_id = ?")
        cursor = connection.cursor()
        cursor.execute(subpref_query, (table_id,))
        while True:
            row = cursor.fetchone()
            if not row: break
            domain, prefix, subchunk, addchunk = \
                row[0], row[1], row[2], row[3]
            if not prefix:
                prefix = struct.unpack("=I", domain)[0]
            else:
                prefix = struct.unpack("=I", prefix)[0]
            pref_data = SBHash(prefix, addchunk, subchunk)
            data.subprefixes.append(pref_data)
            data.add_subchunk(subchunk)
        cursor.close()
        # Note that chunk count reported here is the real chunks we have
        # data for. In reality we expect less chunks to exist in the prefix
        # data due to knocking them out.
        print("\nTable: %s\nAddChunks: %d SubChunks: %d AddPrefixes: %d " \
              "SubPrefixes: %d" % (table_name, len(data.addchunks),
                                   len(data.subchunks), len(data.addprefixes),
                                   len(data.subprefixes)))
        data.sort_all_data()
        sb_names[table_name] = data
    connection.close()
    return sb_names

def compare_table(old_table, new_table):
    verbose = False

    total_prefixes = 0
    failed_prefixes = 0

    # Compare AddPrefixes
    old_addprefixes = set()
    for pref in old_table.addprefixes:
        old_addprefixes.add(pref)

    new_addprefixes = set()
    for pref in new_table.addprefixes:
        new_addprefixes.add(pref)

    total_prefixes += len(old_addprefixes)
    symm_intersec = old_addprefixes ^ new_addprefixes
    failed_prefixes += len(symm_intersec)
    print("%d add mismatches" % len(symm_intersec))

    if verbose:
        for pref in symm_intersec:
            if pref in new_addprefixes:
                print("No match AddPrefix new %X" % pref.prefix)
            elif pref in old_addprefixes:
                print("No match AddPrefix old %X" % pref.prefix)
            else:
                print("wut?")

    # Compare SubPrefixes
    old_subprefixes = set()
    for pref in old_table.subprefixes:
        old_subprefixes.add(pref)

    new_subprefixes = set()
    for pref in new_table.subprefixes:
        new_subprefixes.add(pref)

    total_prefixes += len(old_subprefixes)
    symm_intersec = old_subprefixes ^ new_subprefixes
    failed_prefixes += len(symm_intersec)
    print("%d sub mismatches" % len(symm_intersec))

    if verbose:
        for pref in symm_intersec:
            if pref in new_subprefixes:
                print("No match SubPrefix new %X" % pref.prefix)
            elif pref in old_addprefixes:
                print("No match SubPrefix old %X" % pref.prefix)
            else:
                print("wut?")

    print("Correct: %f%%"
          % ((total_prefixes - failed_prefixes)*100/total_prefixes))
    return failed_prefixes != 0

def compare_all_the_things(new_lists, old_lists):
    failure = False
    for table in old_lists:
        print("\nComparing table " + table)
        old_data = old_lists[table]
        new_data = new_lists[table]
        failure |= compare_table(old_data, new_data)
    return failure

def main(argv):
    new_profile_dir = argv.pop()
    old_profile_dir = argv.pop()
    new_lists = parse_new_databases(new_profile_dir)
    old_lists = parse_old_database(old_profile_dir)
    failure = compare_all_the_things(new_lists, old_lists)
    if failure:
        exit(1)
    else:
        exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Need to specify 2 profile directories.")
        exit(1)
    main(sys.argv)
