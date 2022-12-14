import http.server
import logging
import os
import socket
import socketserver
from datetime import *
from enum import Enum
from http import HTTPStatus
from threading import Thread, current_thread
from typing import List, NamedTuple

from construct import *
from numpy import *
from recordclass import RecordClass, recordclass


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(HTTPStatus.OK)
        self.end_headers()


port = int(os.getenv('PORT', 8080))
print('Listening on port %s' % (port))
httpd = socketserver.TCPServer(('', port), Handler)

def _xprint(*args, **kwargs):
    """Wrapper function around print() that prepends the current thread name"""
    print("[", current_thread().name, "]",
          " ".join(map(str, args)), **kwargs)

def serve_tcp_forever(httpd):
    with httpd:  # to make sure httpd.server_close is called
        _xprint("server about to serve forever (infinite request loop)")
        httpd.serve_forever()
        _xprint("server left infinite request loop")
        
tcp_thread = Thread(target=serve_tcp_forever, args=(httpd, ))

IPAddress = Struct(
    "address" / CString("utf8"),
    "port" / Int16ub
)

MasterServerListResponsePacket = Struct(
    "packet_type" / Int8ub, 
    "flags" / Int8ub,       
    "session_key" / Int32sn,            
    "packet_index" / Int16ub,
    "packet_total" / Int16ub,
    "server_count" / Int16ub,
    "type" / Byte,
    "ip" / IPAddress,
)



#class ServerInfo(NamedTuple):
#    Address: IPAddress
#    GameType: str
#    MissionType: str
#    MaxPlayers: Int32sb
#    Region: Int32ub
#    Version: Int32ub
#    Flags: Int16ub
#    BotCount: Int16ub
#    CPUSpeed: Int32ub
#    PlayerCount: Int32sb
#    PlayerList: List[int] = []
 

class PacketTypes(Enum):
    MasterServerGameTypesRequest  = 2
    MasterServerGameTypesResponse = 4
    MasterServerListRequest       = 6
    MasterServerListResponse      = 8
    GameMasterInfoRequest         = 10
    GameMasterInfoResponse        = 12
    GamePingRequest               = 14
    GamePingResponse              = 16
    GameInfoRequest               = 18
    GameInfoResponse              = 20
    GameHeartbeat                 = 22
    GGCPacket                     = 24
    ConnectChallengeRequest       = 26
    ConnectChallengeReject        = 28
    ConnectChallengeResponse      = 30
    ConnectRequest                = 32
    ConnectReject                 = 34
    ConnectAccept                 = 36
    Disconnect                    = 38
    MasterServerExtendedListResponse = 40
    MasterServerChallenge            = 42
    MasterServerExtendedListRequest  = 44

class Session(RecordClass):
    SessionID: uintc
    Key: uintc
    CreatedDate: timedelta
    Heartbeat: timedelta
    
class Sessions:
    def __init__(self) -> None:
        self.sessions = {}
        self.creation_time= datetime.now()
        self.logger = logging.getLogger('Sessions')
        self.logger.setLevel('INFO')
        
    def has_session(self, ip_address):
        return ip_address in self.sessions
    
    def heartbeat(self, ip_address):
        result = False
        if self.has_session(ip_address):
            self.sessions[ip_address].Heartbeat = self.creation_time - datetime.now()
            result = True
        return result
    
    def get_session(self, ip_address):
        return self.sessions.get(ip_address)
    
    def create_session(self, ip_address):
        if self.has_session(ip_address):
            raise Exception("Cannot creation session for address {address}".format(address= ip_address))
        
        uint16_min = iinfo(uint16).min
        uint16_max = iinfo(uint16).max
        
        new_session = Session(
            SessionID = random.randint(uint16_min, uint16_max, dtype=uintc),
            Key = random.randint(uint16_min, uint16_max, dtype=uintc),
            CreatedDate = self.creation_time - datetime.now(),
            Heartbeat = self.creation_time - datetime.now()
        )

        self.sessions[ip_address] = new_session
        
        return new_session

def process_message_from_client(ip_address, message_from_client, session_manager):
    message = message_from_client[0]
    print(message_from_client[1])
    # address = IPAddress.build(dict(address= message_from_client[1][0], port= message_from_client[1][1]))
    packet_type= Byte.parse(message[:1]) 
    process_packet_type(packet_type, ip_address, message, session_manager)
    return None

def process_packet_type(packet_type, ip_address, stream, session_manager):
    if packet_type == PacketTypes.MasterServerGameTypesRequest:
        print("Received MasterServerGameTypesRequest packet...")
    if packet_type == PacketTypes.MasterServerGameTypesResponse:
        print("Received MasterServerGameTypesResponse packet...")
    if packet_type == PacketTypes.MasterServerListRequest:
        print("Received MasterServerListRequest packet...")
        process_master_server_list_request(ip_address, stream, session_manager)
    if packet_type == PacketTypes.MasterServerListResponse:
        print("Received MasterServerListResponse packet...")
    if packet_type == PacketTypes.GameMasterInfoRequest:
        print("Received GameMasterInfoRequest packet...")
    if packet_type == PacketTypes.GameMasterInfoResponse:
        print("Received GameMasterInfoResponse packet...")
    if packet_type == PacketTypes.GamePingRequest:
        print("Received GamePingRequest packet...")
    if packet_type == PacketTypes.GamePingResponse:
        print("Received GamePingResponse packet...")
    if packet_type == PacketTypes.GameInfoRequest:
        print("Received GameInfoRequest packet...")
    if packet_type == PacketTypes.GameInfoResponse:
        print("Received GameInfoResponse packet...")
    if packet_type == PacketTypes.GameHeartbeat:
        print("Received GameHeartbeat packet...")
        process_game_heartbeat(ip_address, stream, session_manager)
    if packet_type == PacketTypes.GGCPacket:
        print("Received GGCPacket packet...")
    if packet_type == PacketTypes.ConnectChallengeRequest:
        print("Received ConnectChallengeRequest packet...")
    if packet_type == PacketTypes.ConnectChallengeReject:
        print("Received ConnectChallengeReject packet...")
    if packet_type == PacketTypes.ConnectChallengeResponse:
        print("Received ConnectChallengeResponse packet...")
    if packet_type == PacketTypes.ConnectRequest:
        print("Received ConnectRequest packet...")
    if packet_type == PacketTypes.ConnectReject:
        print("Received ConnectReject packet...")
    if packet_type == PacketTypes.ConnectAccept:
        print("Received ConnectAccept packet...")
    if packet_type == PacketTypes.Disconnect:
        print("Received Disconnect packet...")
    if packet_type == PacketTypes.MasterServerExtendedListResponse:
        print("Received MasterServerExtendedListResponse packet...")
    if packet_type == PacketTypes.MasterServerChallenge:
        print("Received MasterServerChallenge packet...")
    if packet_type == PacketTypes.MasterServerExtendedListRequest:
        print("Received MasterServerExtendedListRequest packet...")
        
def process_master_server_list_request(ip_address, stream, session_manager):
    game_type_length = Struct(
        Padding(7),
        "length" / Int8ub,
    )

    gtl = game_type_length.parse(stream)
    
    mission_type_length = Struct(
        Padding(8 + gtl.length),
        "length" / Int8ub,
    )

    mtl = mission_type_length.parse(stream)

    session_key= Struct(
        Padding(2),
        "session_key" / Int32sn,
    )

    sk = session_key.parse(stream)
    session_key = sk.session_key
    
    left_mask = 0xFFFF0000
    right_mask = 0x0000FFFF
    
    session = Int32sb.parse(Int32sb.build((session_key & left_mask) >> 16))
    key = Int32sb.parse(Int32sb.build(session_key & right_mask))
    
    format = Struct(
        "packet_type" / Int8ub, 
        "flags" / Int8ub,       
        "session_key" / Int32sn,            
        "pad" / Int8ub,         
        "game_type_length" / Int8ub, 
        "game_type" / PaddedString(gtl.length, "ascii"),
        "mission_type_length" / Int8ub,
        "mission_type" / PaddedString(mtl.length, "ascii"),
        "min_players" / Int8ub,
        "max_players" / Int8ub,
        "version" / Int32ub,
        "filter_flags" / Int8ub,
        "max_bots" / Int8ub,
        "min_cpu" / Int16ub,
        "buddy_count" / Int8ub,
    )

    packet = format.parse(stream)
    print("Packet Type: ", packet.packet_type)
    print("Flags: ", packet.flags)
    print("Session Key: ", packet.session_key)
    print("Session: ", session)
    print("Key: ", key)
    print("Game Type: ", packet.game_type)
    print("Mission Type: ", packet.mission_type)


def get_session_key_pair(stream, pad_bytes= 1):
    session_key= Struct(
        Padding(pad_bytes),
        "session_key" / Int32sn,
    )

    sk = session_key.parse(stream)
    print("SK: ", sk)
    session_key = sk.session_key
    
    left_mask = 0xFFFF0000
    right_mask = 0x0000FFFF
    
    session = Int32sb.parse(Int32sb.build((session_key & left_mask) >> 16))
    key = Int32sb.parse(Int32sb.build(session_key & right_mask))

    return (session, key)


def process_game_heartbeat(ip_address, stream, session_manager):
    
    if not session_manager.heartbeat(ip_address):
        session_manager.create_session(ip_address)

    session_key_pair= get_session_key_pair(stream, pad_bytes=2)

    print(session_key_pair)
    
    #session_key= Struct(
    #    Padding(2),
    #    "session_key" / Int32sn,
    #)

    #sk = session_key.parse(stream)
    #session_key = sk.session_key
    
    #left_mask = 0xFFFF0000
    #right_mask = 0x0000FFFF
    
    #session = Int32sb.parse(Int32sb.build((session_key & left_mask) >> 16))
    #key = Int32sb.parse(Int32sb.build(session_key & right_mask))
    
    #format = Struct(
    #    "packet_type" / Int8ub,
    #    "flags" / Int8ub,
    #    "session_key" / Int16sn,
    #)
    #result = format.parse(stream)

localIP     = "0.0.0.0"
localPort   = 20001
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((localIP, localPort))

print("Master server up and listening")

def serve_udp_forever(udp_socket):
    with udp_socket:
        bufferSize  = 1024
        sessions = Sessions()
        _xprint("UDP server about to serve forever (infinite request loop)")
        while True:
            message_from_client = udp_socket.recvfrom(bufferSize)  
            ip_address = message_from_client[1]
            
            message_to_client = process_message_from_client(ip_address, message_from_client, sessions)    

            if message_to_client != None:
                udp_socket.sendto(message_to_client, ip_address)
        _xprint("UDP server left infinite request loop")
        
udp_thread = Thread(target=serve_udp_forever, args=(UDPServerSocket, ))
udp_thread.start()


tcp_thread.start()