import socket
#from numpy import *
from enum import Enum
from typing import NamedTuple, List
from datetime import *
import logging
from construct import *
import os
import http.server
import socketserver
from http import HTTPStatus
from threading import Thread, current_thread


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
tcp_thread.start()

localIP     = "0.0.0.0"
localPort   = 20001
bufferSize  = 1024

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

class IPAddress(NamedTuple):
    Address: str
    Port: Int32sb

class ServerInfo(NamedTuple):
    IPAddress: IPAddress
    GameType: str
    MissionType: str
    MaxPlayers: Int32sb
    Region: Int32ub
    Version: Int32ub
    Flags: Int16ub
    BotCount: Int16ub
    CPUSpeed: Int32ub
    PlayerCount: Int32sb
    PlayerList: List[int] = []
    
def Session(NamedTuple):
    SessionID: uint16
    Key: uint16
    CreatedDate: timedelta
    Heartbeat: timedelta
    
class Sessions(object):
    def __init__(self) -> None:
        self.sessions = {}
        self.creation_time= datetime.now()
        self.logger = logging.getLogger('Sessions')
        
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
            SessionID = random.randint(uint16_min, uint16_max, dtype=uint16),
            Key = random.randint(uint16_min, uint16_max, dtype=uint16),
            CreatedDate = self.creation_time - datetime.now(),
            Heartbeat = self.creation_time - datetime.now()
        )
        
        self.logger.info("{addr} Session: {id}, Key: {key}".format(addr=ip_address, id=new_session.SessionID, key=new_session.Key))

        self.sessions[ip_address] = new_session
        
        return new_session

def process_message_from_client(message_from_client):
    message = message_from_client[0]
    address = message_from_client[1]
    packet_type= Byte.parse(message[:1]) 
    print("Packet type: ", packet_type)
    process_packet_type(packet_type, message)
    return None

def process_packet_type(packet_type, stream):
    if packet_type == PacketTypes.MasterServerGameTypesRequest:
        print("Received MasterServerGameTypesRequest packet...")
    if packet_type == PacketTypes.MasterServerGameTypesResponse:
        print("Received MasterServerGameTypesResponse packet...")
    if packet_type == PacketTypes.MasterServerListRequest:
        print("Received MasterServerListRequest packet...")
        process_master_server_list_request(stream)
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
        process_game_heartbeat(stream)
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
        
def process_master_server_list_request(stream):
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
    
    format = Struct(
        "packet_type" / Int8ub, 
        "flags" / Int8ub,       
        "session" / Int16ub,    
        "key" / Int16ub,        
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

    result = format.parse(stream)
    print(result)

def process_game_heartbeat(stream):
    format = Struct(
        "packet_type" / Int8ub,
        "flags" / Int8ub,
        "session" / Int16ub,
        "key" / Int16ub,
    )
    result = format.parse(stream)
    print(result)

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((localIP, localPort))

sessions = Sessions()

print("Master server up and listening")

def serve_udp_forever(udp_socket, session_manager):
    while True:
        message_from_client = udp_socket.recvfrom(bufferSize)  
        address = message_from_client[1]
        
        message_to_client = process_message_from_client(message_from_client)    

        if message_to_client != None:
            udp_socket.sendto(message_to_client, address)
        
udp_thread = Thread(target=serve_udp_forever, args=(UDPServerSocket, sessions, ))
udp_thread.start()