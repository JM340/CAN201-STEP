from socket import *
import json
import os
from os.path import join, getsize
import argparse
import time
import logging
import struct
import hashlib
import gzip
import zipfile
from logging.handlers import TimedRotatingFileHandler
import base64
import uuid
import math

OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

MAX_PACKAGE_SIZE = 20480

def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("-server_ip", default='127.0.0.1', action='store', required=False, dest="ip",
                       help="The IP address bind to the server. Default bind all IP.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    parse.add_argument("-id","--id",default='2010820',action='store',required=False,dest='id',help='Your id')
    parse.add_argument("-f","-path",default='',action='store',required=False,dest='file_path',
                        help='upload file path, default is NONE')          
    return parse.parse_args()

#TCP class
class TCPClient:
    #connect server
    def __init__(self,parser):
        self.ip = parser.ip
        self.port = parser.port
        self.id = parser.id
        self.file = parser.file_path
        self.clientsocket = socket(AF_INET,SOCK_STREAM)
        self.clientsocket.connect((self.ip,(int)(self.port)))
        
    def make_packet(self,json_data,bin_data = None):
        j = json.dumps(dict(json_data),ensure_ascii=False)
        j_len = len(j)
        if bin_data is None:
            return struct.pack('!II',j_len,0) + j.encode()
        else:
            return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data
    
    def make_request_data(self,request_type,request_operation,json_data,bin_data=None):
        json_data[FIELD_TYPE] = request_type
        json_data[FIELD_OPERATION] = request_operation
        json_data[FIELD_DIRECTION] = DIR_REQUEST
        return self.make_packet(json_data,bin_data)
    
    def get_tcp_packet(self):
        bin_data = b''
        while len(bin_data) < 8:
            data_rec = self.clientsocket.recv(8)
            if data_rec == b'':
                time.sleep(0.01)
            if data_rec == b'':
                return None, None
            bin_data += data_rec
        data = bin_data[:8]
        bin_data = bin_data[8:]
        j_len, b_len = struct.unpack('!II', data)
        while len(bin_data) < j_len:
            data_rec = self.clientsocket.recv(j_len)
            if data_rec == b'':
                time.sleep(0.01)
            if data_rec == b'':
                return None, None
            bin_data += data_rec
        j_bin = bin_data[:j_len]

        try:
            json_data = json.loads(j_bin.decode())
        except Exception as ex:
            return None, None

        bin_data = bin_data[j_len:]
        while len(bin_data) < b_len:
            data_rec = self.clientsocket.recv(b_len)
            if data_rec == b'':
                time.sleep(0.01)
            if data_rec == b'':
                return None, None
            bin_data += data_rec
        return json_data, bin_data
        
    def comm(self):
        try:
            # Random LOGIN Writing
            self.clientsocket.send(
                self.make_request_data(
                    TYPE_AUTH,OP_LOGIN,
                    {
                        FIELD_USERNAME: self.id,
                        FIELD_PASSWORD: hashlib.md5(self.id.encode()).hexdigest().lower()
                    }
                )
            )
            json_data, bin_data = self.get_tcp_packet()
            print(json_data[FIELD_TOKEN])
            token = json_data[FIELD_TOKEN]
            
            self.clientsocket.send(
                self.make_request_data(
                    TYPE_FILE,OP_SAVE,
                    {
                        FIELD_TOKEN: token,
                        FIELD_KEY: self.file,
                        FIELD_SIZE: len(open(self.file, 'rb').read())
                    }
                )
            )
            json_data, bin_data = self.get_tcp_packet()
            print(json_data)
            #init block index
            block_size = 0
            #read file.bin
            with open(self.file, 'rb') as f:
                while(True):
                    file_data = f.read(MAX_PACKAGE_SIZE)
                    if not file_data:
                        break
                    #send data
                    self.clientsocket.send(
                        self.make_request_data(
                            TYPE_FILE,OP_UPLOAD,
                            {
                                FIELD_TOKEN: token,
                                FIELD_KEY: self.file,
                                FIELD_SIZE: len(file_data),
                                FIELD_BLOCK_INDEX: block_size
                            },file_data
                        )
                    )
                    #add block data
                    block_size+=1
                    json_data, bin_data  = self.get_tcp_packet()
                    print(json_data)


                    
        except socket.error as se:
            print(f'Socket Error: {str(se)}')
        except Exception as e:
            print(f'Other Exception: {str(e)}')
        finally:
            self.clientsocket.close()
    
    
def main():
    parser = _argparse()
    tcpClient = TCPClient(parser)
    tcpClient.comm()


if __name__ == '__main__':
    main()

