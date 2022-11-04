import socket
from bitstream import BitStream
from numpy import *
from enum import Enum

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


def process_message(message):
    stream = BitStream(message)
    packet_type = stream.read(uint8, 1).item(0) 
    process_packet_type(packet_type, stream)

def process_packet_type(packet_type, stream):
    if packet_type == PacketTypes.MasterServerGameTypesRequest.value:
        print("Received MasterServerGameTypesRequest packet...")
    if packet_type == PacketTypes.MasterServerGameTypesResponse.value:
        print("Received MasterServerGameTypesResponse packet...")
    if packet_type == PacketTypes.MasterServerListRequest.value:
        print("Received MasterServerGameTypesResponse packet...")
        process_master_server_list_request(stream)
    if packet_type == PacketTypes.MasterServerListResponse.value:
        print("Received MasterServerListResponse packet...")
    if packet_type == PacketTypes.GameMasterInfoRequest.value:
        print("Received GameMasterInfoRequest packet...")
    if packet_type == PacketTypes.GameMasterInfoResponse.value:
        print("Received GameMasterInfoResponse packet...")
    if packet_type == PacketTypes.GamePingRequest.value:
        print("Received GamePingRequest packet...")
    if packet_type == PacketTypes.GamePingResponse.value:
        print("Received GamePingResponse packet...")
    if packet_type == PacketTypes.GameInfoRequest.value:
        print("Received GameInfoRequest packet...")
    if packet_type == PacketTypes.GameInfoResponse.value:
        print("Received GameInfoResponse packet...")
    if packet_type == PacketTypes.GameHeartbeat.value:
        print("Received GameHeartbeat packet...")
        process_game_heartbeat(stream)
    if packet_type == PacketTypes.GGCPacket.value:
        print("Received GGCPacket packet...")
    if packet_type == PacketTypes.ConnectChallengeRequest.value:
        print("Received ConnectChallengeRequest packet...")
    if packet_type == PacketTypes.ConnectChallengeReject:
        print("Received ConnectChallengeReject packet...")
    if packet_type == PacketTypes.ConnectChallengeResponse.value:
        print("Received ConnectChallengeResponse packet...")
    if packet_type == PacketTypes.ConnectRequest.value:
        print("Received ConnectRequest packet...")
    if packet_type == PacketTypes.ConnectReject.value:
        print("Received ConnectReject packet...")
    if packet_type == PacketTypes.ConnectAccept.value:
        print("Received ConnectAccept packet...")
    if packet_type == PacketTypes.Disconnect.value:
        print("Received Disconnect packet...")
    if packet_type == PacketTypes.MasterServerExtendedListResponse.value:
        print("Received MasterServerExtendedListResponse packet...")
    if packet_type == PacketTypes.MasterServerChallenge.value:
        print("Received MasterServerChallenge packet...")
    if packet_type == PacketTypes.MasterServerExtendedListRequest.value:
        print("Received MasterServerExtendedListRequest packet...")
        
def process_master_server_list_request(stream):
    query_flags= stream.read(uint8, 1)
    sequence_number= stream.read(int32, 1)
    packet_index= stream.read(uint8, 1)
    game_type_length= stream.read(uint8, 1)
    game_type= stream.read(bytes, game_type_length)
    mission_type_length= stream.read(uint8, 1)
    mission_type= stream.read(bytes, mission_type_length)
    min_players= stream.read(uint8, 1)
    max_players= stream.read(uint8, 1)
    version= stream.read(uint32, 1)
    filter_flags= stream.read(uint8, 1)
    max_bots= stream.read(uint8, 1)
    min_cpu= stream.read(uint16, 1)
    buddy_count= stream.read(uint8, 1)
    
    print(query_flags, 
        sequence_number, 
        packet_index, 
        game_type, 
        mission_type, 
        min_players, 
        max_players, 
        version, 
        filter_flags, 
        max_bots,
        min_cpu,
        buddy_count)

def process_game_heartbeat(stream):
    query_flags= stream.read(uint8, 1)
    session = stream.read(uint32, 1)
    print(query_flags, session)

localIP     = "127.0.0.1"
localPort   = 20001
bufferSize  = 1024

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))

print("Master server up and listening")
 

# Listen for incoming datagrams
while(True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    process_message(message)
    

    #clientMsg = "Message from Client:{}".format(message)
    clientIP  = "Client IP Address:{}".format(address)
    
    #print(clientMsg)
    print(clientIP)

    # Sending a reply to client
    #UDPServerSocket.sendto(bytesToSend, address)