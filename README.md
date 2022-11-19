# torque-master-server

# What I think this thing needs to do

1. Client(s) looking to join a game

   - Client(s) send MasterServerListRequest to master server
   - This thing identifies client and sends back a list of game servers

2. Client(s) hosting a game
   - Client hosts a game, game sends GameHeartbeat packet to master server with ip address/port, key:0, session:increases each time heartbeat packet sent
     - Master server sends GameMasterInfoRequest packet to ip address/port from heartbeat
     - Client sends GameMasterInfoResponse packet to master server

# What is left to do

...still figuring it all out.
