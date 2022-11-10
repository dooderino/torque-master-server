# torque-master-server

# What I think this thing needs to do

1. Client(s) looking to join a game

   - Client(s) send requests to this thing
   - This thing identifies client and sends back a list of game servers

2. Client(s) hosting a game
   - Client hosts a game, game sends heartbeat to this thing, with ip address, key:0, session:some number
   - This thing adds client game to a server list of some kind
     - To do that, this thing needs to
       - Generate key, store key, session, and address

# What is left to do

...still figuring it all out.
