
from neo.IO.Mixins import SerializableMixin
#from neo.Network.LocalNode import LocalNode
from neo.Network.Payloads.NetworkAddressWithTime import NetworkAddressWithTime
from neo.Core.Blockchain import Blockchain

import sys
import ctypes
import datetime


class VersionPayload(SerializableMixin):


    Version=None
    Services = None
    Timestamp = None
    Port = None
    Nonce = None
    UserAgent = None
    StartHeight = 1
    Relay = False

    def __init__(self, port=None, nonce=None, userAgent=None):
        if port and nonce and userAgent:
#            self.Version = LocalNode.PROTOCOL_VERSION
#using LocalNode.PROTOCOL_VERSION makes circular import error
            self.Port = port
            self.Version = 0
            self.Services = NetworkAddressWithTime.NODE_NETWORK
            self.Timestamp = int(datetime.datetime.utcnow().timestamp())
            self.Nonce = nonce
            self.UserAgent = userAgent

            if Blockchain.Default() is not None and Blockchain.Default().Height() is not None:
                self.StartHeight = Blockchain.Default().Height()

            self.Relay = True

        print("created version: %s " % self.StartHeight)

    def Size(self):
        return ctypes.sizeof(ctypes.c_uint) + ctypes.sizeof(ctypes.c_ulong) + ctypes.sizeof(ctypes.c_uint) + \
                ctypes.sizeof(ctypes.c_ushort) + ctypes.sizeof(ctypes.c_uint) + \
                  sys.getsizeof(self.UserAgent) + ctypes.sizeof(ctypes.c_uint) + ctypes.sizeof(ctypes.c_bool)


    def Deserialize(self, reader):
        self.Version = reader.ReadUInt8()
        self.Services = reader.ReadUInt64()
        self.Timestamp = reader.ReadUInt32()
        self.Port = reader.ReadUInt16()
        self.Nonce = reader.ReadUInt32()
        self.UserAgent = reader.ReadVarString().decode('utf-8')
        self.StartHeight = reader.ReadUInt32()
        self.Relay = reader.ReadBool()

    def Serialize(self, writer):
        writer.WriteUInt8(self.Version)
        writer.WriteUInt64(self.Services)
        writer.WriteUInt32(self.Timestamp)
        writer.WriteUInt16(self.Port)
        writer.WriteUInt32(self.Nonce)
        writer.WriteVarString(self.UserAgent)
        writer.WriteUInt32(self.StartHeight)
        writer.WriteBool(self.Relay)