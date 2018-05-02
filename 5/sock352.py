# sock352.py 

# (C) 2018 by R. P. Martin, under the GPL license, version 2.

# this is the skeleton code that defines the methods for the sock352 socket library, 
# which implements a reliable, ordered packet stream using go-back-N.
#
# Note that simultaneous close() is required, does not support half-open connections ---
# that is outstanding data if one side closes a connection and continues to send data,
# or if one side does not close a connection the protocol will fail. 

import socket as ip
import random
import binascii
import threading
import time
import sys
import struct as st
import os
import signal

# The first byte of every packet must have this value 
MESSAGE_TYPE = 0x44

# this defines the sock352 packet format.
# ! = big endian, b = byte, L = long, H = half word
HEADER_FMT = '!bbLLH'

# this are the flags for the packet header 
SYN =  0x01    # synchronize 
ACK =  0x02    # ACK is valid 
DATA = 0x04    # Data is valid 
FIN =  0x08    # FIN = remote side called close 

def has_syn(b):
    return b & SYN

def has_ack(b):
    return b & ACK

def has_data(b):
    return b & DATA

def has_fin(b):
    return b & FIN

# max size of the data payload is 63 KB
MAX_SIZE = (63*1024)

# max size of the packet with the headers 
MAX_PKT = ((16+16+16)+(MAX_SIZE))

# these are the socket states 
STATE_INIT = 1
STATE_SYNSENT = 2
STATE_LISTEN  = 3
STATE_SYNRECV = 4 
STATE_ESTABLISHED = 5
STATE_CLOSING =  6
STATE_CLOSED =   7
STATE_REMOTE_CLOSED = 8


sock352_dbg_level = 5
# function to print. Higher debug levels are more detail
# highly recommended 
def dbg_print(level,string):
    global sock352_dbg_level 
    if (sock352_dbg_level >=  level):
        print string 
    return 
      

# This class holds the data of a packet gets sent over the channel 
# 
class Packet:
    def __init__(self):
        self.type = MESSAGE_TYPE    # ID of sock352 packet
        self.cntl = 0               # control bits/flags 
        self.seq = 0                # sequence number 
        self.ack = 0                # acknowledgement number 
        self.size = 0               # size of the data payload 
        self.data = b''             # data 

    @staticmethod
    def synsent(seq):
        pkt = Packet()
        pkt.cntl = SYN
        pkt.seq = seq
        return pkt

    @staticmethod
    def synrcv(synsent, seq):
        pkt = Packet()
        pkt.cntl = SYN | ACK
        pkt.ack = synsent.seq
        pkt.seq = seq
        return pkt

    @staticmethod
    def ack(pkt):
        ack = Packet()
        ack.cntl = ACK
        ack.seq = 0
        ack.ack = pkt.seq

        return ack

    @staticmethod
    def data(buf, seq):
        pkt = Packet()
        pkt.cntl = DATA
        pkt.size = len(buf)
        pkt.data = buf
        pkt.seq = seq

        return pkt

    @staticmethod
    def fin(seq):
        pkt = Packet()
        pkt.cntl = FIN
        pkt.seq = seq

        return pkt

    @staticmethod
    def from_bytes(buf):
        pkt = Packet()
        pkt.unpack(buf)
        return pkt

    def is_synsent(self):
        return (self.cntl == SYN) and (self.ack == 0)

    def is_synrcv(self, synsent):
        return (self.cntl == SYN | ACK) and (self.ack == synsent.seq)

    def is_ack(self):
        return (self.cntl == ACK)

    def is_data(self):
        return (self.cntl == DATA)

    def is_fin(self):
        return (self.cntl == FIN)

    # unpack a binary byte array into the Python fields of the packet 
    def unpack(self,bytes):
        # check that the data length is at least the size of a packet header 
        data_len = (len(bytes) - st.calcsize('!bbLLH'))
        if (data_len >= 0): 
            new_format = HEADER_FMT + str(data_len) + 's'
            values = st.unpack(new_format,bytes)
            self.type = values[0]
            self.cntl = values[1]
            self.seq  = values[2]
            self.ack  = values[3]
            self.size = values[4] 
            self.data = values[5]
            # you dont have to have to implement the the dbg_print function, but its highly recommended 
            dbg_print (1,("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data))))
        else:
            dbg_print (2,("sock352 error: bytes to packet unpacker are too short len %d %d " % (len(bytes), st.calcsize('!bbLLH'))))

        return
    
    # returns a byte array from the Python fields in a packet 
    def pack(self):
        if (self.data == None): 
            data_len = 0
        else:
            data_len = len(self.data)
        if (data_len == 0):
            bytes = st.pack('!bbLLH',self.type,self.cntl,self.seq,self.ack,self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s' 
            dbg_print(5,("cs352 pack: %d %d %d %d %d %s " % (self.type,self.cntl,self.seq,self.ack,self.size,self.data)))
            bytes = st.pack(new_format,self.type,self.cntl,self.seq,self.ack,self.size,self.data)
        return bytes
    
    # this converts the fields in the packet into hexadecimal numbers 
    def toHexFields(self):
        if (self.data == None):
            retstr=  ("type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr

    # this converts the whole packet into a single hexidecimal byte string (one hex digit per byte)
    def toHex(self):
        if (self.data == None):
            retstr=  ("%x%x%x%xx%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("%x%x%x%x%xx%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr

# A received packet with a matching ack
# is removed from the list of outstanding packets.

# the main socket class
# you must fill in all the methods
# it must work against the class client and servers
# with various drop rates

class Socket:

    def __init__(self):
        self.state = STATE_INIT
        self.debug_level = 0
        self.sock = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)

        self.timeout = 0.1 # TODO check various timeouts against bandwidth test

        self.remote_addr = None
        self.next_seq_recv = None
        self.next_seq_send = 9

        # TODO check dict vs list for bandwidth test
        self.sent_unacked = dict()
        self.recv_buffered = dict()

    # Print a debugging statement line
    # 
    # 0 == no debugging, greater numbers are more detail.
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_debug_level(self, level):
        pass

    # Set the % likelihood to drop a packet
    #
    # you do not need to implement the body of this method,
    # but it must be in the library,
    def set_drop_prob(self, probability):
        pass 

    # Set the seed for the random number generator to get
    # a consistent set of random numbers
    # 
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_random_seed(self, seed):
        self.random_seed = seed 
        

    # bind the address to a port
    # You must implement this method
    #
    def bind(self,address):
        if self.state != STATE_INIT:
            raise ip.error("socket is already in use")

        self.sock.bind(address)
        dbg_print(1, "Bound to address {}".format(address))

    # connect to a remote port
    # You must implement this method
    def connect(self,address):
        self.remote_addr = address

        synsent = Packet.synsent(self.next_seq_send)
        self.next_seq_send+=1
        self.sock.sendto(synsent.pack(), self.remote_addr)

        dbg_print(1, "synsent sent with seq {}".format(synsent.seq))
        self.state = STATE_SYNSENT
        
        buf, _ = self.sock.recvfrom(MAX_PKT)
        synrcv = Packet.from_bytes(buf)
        if not synrcv.is_synrcv(synsent):
            dbg_print(0, synrcv.toHexFields)
            raise ip.error("error, packet after synsent was not synrcv")

        dbg_print(1, "synrcv successfully received, seq {}".format(synrcv.seq))
        self.next_seq_recv = synrcv.seq+1

        dbg_print(1, "sending ack to synrcv")
        synrcv_ack = Packet.ack(synrcv)
        self.sock.sendto(synrcv_ack.pack(), self.remote_addr)

        self.state = STATE_ESTABLISHED
        dbg_print(1, "connection established")


        self.sock.settimeout(self.timeout)

    #accept a connection
    def accept(self):
        if self.state != STATE_INIT:
            dbg_print(0, "Socket is already in use.")

        # not really useful since we wait here, i.e. state is never visible
        self.state = STATE_LISTEN

        buf, addr = self.sock.recvfrom(MAX_PKT)
        self.remote_addr = addr

        synsent = Packet.from_bytes(buf)
        if not synsent.is_synsent():
            dbg_print(0, synsent.toHexFields())
            raise ip.error("error, first connection packet was not synsent")

        dbg_print(1, "Synsent received, seq {}".format(synsent.seq))
        synrcv = Packet.synrcv(synsent, self.next_seq_send)
        self.sock.sendto(synrcv.pack(), self.remote_addr)
        self.next_seq_recv = synsent.seq+1
        self.next_seq_send += 1

        # acks don't get dropped so this is guaranteed
        self.state = STATE_ESTABLISHED
        dbg_print(1, "connection established")

        self.sock.settimeout(self.timeout)
        

        # technically we are supposed to return a new socket from this, just return self
        return (self, self.sock.getsockname())

    # send a message up to MAX_DATA
    # You must implement this method     
    def sendto(self,buffer):
        if self.state == STATE_ESTABLISHED:
            pkt = Packet.data(buffer, self.next_seq_send)

            self.sock.sendto(pkt.pack(), self.remote_addr)
            self.add_sent_unacked(pkt)
            return len(buffer)

        elif self.state == STATE_CLOSING:
            pass
        else: 
            raise ip.error("Socket not connected. Current state: {}".format(self.state))
            

    # receive a message up to MAX_DATA
    # You must implement this method     
    def recvfrom(self,nbytes):
        while True:
            if (self.state == STATE_ESTABLISHED) or (self.state == STATE_REMOTE_CLOSED) or (self.state == STATE_CLOSING):
                data = self.do_recv()
                if data:
                    return data
                if self.state == STATE_CLOSED:
                    return None

            elif self.state == STATE_LISTEN:
                raise ip.error("Socket not connected.")
            else: # init, closed, remoteclosed
                return None

    def do_recv(self):
        buffered_pkt = self.check_recv_buffered()
        if buffered_pkt:
            dbg_print(1, "Buffered packet is available to recv")
            self.next_seq_recv += 1
            # no ack, we already acked when it was received
            return buffered_pkt.data
        try:
            buf, addr = self.sock.recvfrom(MAX_PKT)
            pkt = Packet.from_bytes(buf)
            if pkt.is_ack():
                self.check_sent_unacked(pkt)
                return None

            elif pkt.is_data():
                dbg_print(1, "received data with seq {}".format(pkt.seq))
                if pkt.seq == self.next_seq_recv:
                    dbg_print(1, "sequence number matches expected next seq")
                    self.send_ack(pkt)
                    return pkt.data
                elif pkt.seq > self.next_seq_recv:
                    dbg_print(1, "sequence number is greater than expected, storing packet and resending unacked packets")
                    self.add_recv_buffered(pkt)
                    self.send_ack(pkt)
                    self.resend_sent_unacked()
                else:
                    dbg_print(1, "sequence number is less than current expected, discarding")
                    # if we already received it, ignore
                    return None

            elif pkt.is_fin():
                dbg_print(1, "received fin with seq {}".format(pkt.seq))
                if self.state == STATE_CLOSING:
                    dbg_print(1, "we are in close() and recieved a FIN, CLOSEing")
                    self.state = STATE_CLOSED
                    return None
                dbg_print(1, "recived fin with seq {}".format(pkt.seq))
                self.state = STATE_REMOTE_CLOSED
                self.send_ack(pkt)


        except ip.timeout:
            dbg_print(2, "timeout exceeded, resending unacked packets")
            self.resend_sent_unacked()

    def check_recv_buffered(self):
        return self.recv_buffered.get(self.next_seq_recv)

    def add_recv_buffered(self, pkt):
        self.recv_buffered[pkt.seq] = pkt

    def send_ack(self, pkt):
        ack = Packet.ack(pkt)
        self.sock.sendto(ack.pack(), self.remote_addr)
        self.next_seq_recv += 1

    def send_fin(self):
        fin = Packet.fin(self.next_seq_send)
        self.sock.sendto(fin.pack(), self.remote_addr)
        self.next_seq_send += 1

    def add_sent_unacked(self, pkt):
        self.sent_unacked[pkt.seq] = pkt
        self.next_seq_send+=1
    
    def check_sent_unacked(self, pkt):
        if pkt.ack in self.sent_unacked:
            dbg_print(1, "received ack for packet with our seq {}".format(pkt.ack))
            self.sent_unacked.pop(pkt.ack, None)
        # assuming that we don't get acks for unsent seqs
        else:
            dbg_print(1, "received duplicate ack for packet with our seq {}".format(pkt.ack))

    def resend_sent_unacked(self):
        for pkt in self.sent_unacked.values():
            dbg_print(1, "resending unacked packet with seq {}".format(pkt.seq))
            self.sock.sendto(pkt.pack(), self.remote_addr)
            # do not increase next_seq_send here, since we are already past it

    # close the socket and make sure all outstanding
    # data is delivered 
    # You must implement this method         
    def close(self):
        dbg_print(1, "closing connection")
        if self.state == STATE_REMOTE_CLOSED:
            return
        self.state = STATE_CLOSING

        fin = Packet.fin(self.next_seq_send)
        self.send_fin()
        while len(self.sent_unacked) > 0 and not self.state == STATE_CLOSED:
            # dbg_print(2, "resending unacked packets, waiting for remote close. state {}".format(self.state))
            # dbg_print(2, "{} unacked packets".format(len(self.sent_unacked)))
            # for pkt in self.sent_unacked.values():
            #     dbg_print(4, "type {:x}, seq {}".format(pkt.cntl, pkt.seq))
            _ = self.recvfrom(MAX_SIZE)
        return 
