#!/usr/bin/python

import numpy
import struct

numpy.seterr(over='ignore')


class general(object):
    """General packet encoding tools"""
    def __init__(self):
        self.size = 2048
        self.RandomTable()

    def NextValue(self, lfsr):
        """Linear feedback shift registe thing"""
        return numpy.int32(lfsr >> 1) ^ (-(lfsr & 1) & 0xB400)

    def RandomTable(self):
        """Build table of data we'll XOR against"""
        self.values = bytearray()
        val = numpy.int32(0xACE1)
        for i in range(0, self.size):
            val = numpy.int32(self.NextValue(val))
            self.values.append(numpy.uint8(val))

    def RandMsg(self, i):
        """Grab the associated value from table"""
        return(self.values[i % self.size])


class packet(object):
    """Process packet header and payload"""
    def __init__(self, packetdata):
        """First 24 bytes is header information"""
        self.header = header(packetdata[:24])
        self.payload = payload(
            packetdata,
            self.header.serial
        )


class header(object):
    """Process unencoded packet data header"""
    def __init__(self, bytes):
        """Header is 24 bytes, but have not implemented the ackBitmask union"""
        header = bytes[:16]
        self.data = struct.unpack('HHLLL', header)
        self.length, self.flags, self.crc, self.serial, self.ackOrigin = self.data


class payload(object):
    """Payload processing tool"""
    def __init__(self, bytes, serial):
        self.headerlength = 24
        self.data = bytearray()

        offset = self.Hash(serial)

        for s in range(self.headerlength, len(bytes)):
            #: XOR against our weird "random" table
            self.data.append(ord(bytes[s]) ^ tools.RandMsg(s+offset))

    def Hash(self, seed):
        """Integer hash function"""
        val = (seed ^ 61) ^ (seed >> 16)
        val = val + (val << 3)
        val = val ^ (val >> 4)
        val = int(val * numpy.int32(0x27d4eb2d))
        val = val ^ (val >> 15)
        return (val & 0x7fff)

#: Build XOR table for local use
tools = general()
