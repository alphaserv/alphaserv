require "copas"
require "Json"
require "class"

--!TODO: SSL! FIXME
--require("ssl")

local ip = "127.0.0.1"
local port = 2167
local DEBUG = true

-- TLS/SSL server parameters (omitted)
-- TLS/SSL server parameters
local params = {
	mode		= "server",
	protocol	= "tlsv1",
	key			= "/etc/certs/serverkey.pem",
	certificate	= "/etc/certs/server.pem",
	cafile		= "/etc/certs/CA.pem",
	verify		= {"peer", "fail_if_no_peer_cert"},
	options		= {"all", "no_sslv2"},
	ciphers		= "ALL:!ADH:@STRENGTH",
}

--[[!
	The numeric protocol id
]]
local PROTOCOL_VERSION = 0

--[[!
	The protocol consists of a Json array shaped message with the first element containing the message type id.
	Additional arguments may be passed, too many will be ignored
	
	Example:
	[
		0,
		[
			id,
			hash
		]
	]
	
	will internally result into a call to INITSRV with arguments id and hash.
	
	Invalid message ids should be ignored and won't result into a disconnect.
	The server should keep the connection open at least when players are connected.
	
	Passwords are hashed with the builtin functionallity of sauerbraten and may only be used in combination with /setmaster and /connect.
	NO #login COMMANDS MAY BE USED.
	
	messages end with a \n char
]]

local MSG = {
	--[[!
		Verifies the server by checking the sent id and a hash of the key and a random number sent by the master server.
		Disconnects and won't allow reconnect for some time on failure!
		Protocol_version is the version of the protocol used by the master, newer protocols will wither be backwards compatable or result into a disconnect.
		
		Example master:
		[int:random_number, int:master_protocol_version]
		
		Example server:
		[id, hash, int:server_protocol_version]
	]]
	INITSRV		= 0,
	
	--[[!
		Sends an authentication request to the master.
		This is done on /setmaster or /connect with a password provided
		
				
		example server:
		[name, cn, sessionid, hashedpassword]
		
		example master:
		[cn, sessionid, bool:auth_success]
	]]
	AUTHUSER	= 1,
	
	--[[!
		Checks if:
		- an user's name is reserved (0)
		- the user is using a reserved clantag (1)
		- the user is banned (2)
		
		example server:
		[ip, name]
		
		example master:
		[bool:forceSpec, int:reason]
	]]	
	USERCHECK	= 2,
	
	--[[!
		Global notice for admins/users, mostly newsfeed for admins.
		Example
		"NOTICE: important update ..."
	]]
	GNOTICE		= 3,
	
	--[[!
		Sends an array containing stats of the players that are logged in of the just finished match.
		
		Example:
		[
			{
				name:"unnamed",
				frags:0,
				timeplayed:100, //time that the player was unspeced in the match
				shots:
				...
			},
			{
			...
			}
		]
	]]
	STATGAME	= 4,
	
	--[[!
		Sends an error id and a error string, may occur on master-side errors
	
		Example:
		[2, "Invalid arguments"]
		
		Error ids:
		- 99 unkown error
		- 1 Invalid json
		- 2 Invalid arguments
	]]
	ERROR = 5,
	ERROR_ID = {
		UNKOWN = 99,
		INVALID_JSON = 1,
		INVALID_ARGS = 2
	}
}

--[[! TODO write neo4j module? ]]
local DB = require 'Spore'.new_from_lua {
    base_url = ' http://localhost:7474/db/data/',
    methods = {
        findNode = {
            path = '/node/:id',
            method = 'GET',
            required_params = {
            	"id"
            }
        },
        
        findIndexed = {
			path = '/index/node/:index/:key/:value',
            method = 'GET',
            required_params = {
            	'index',
                'key',
                'value',
            },
        },
        
        findUserByName = {
			path = '/index/node/Name/name/:name',
			method = 'GET',
			required_params = {
				'name'
			}
        }
    },
}

function getRandomNumber()
	return 10
end




function clientHandler(socket)
	local client = copas.wrap(socket)
	local info = {socket:getpeername()}
	info.ip, info.port = info[1], info[2]
	
	function client:sendCommand(id, ...)
		local arg = {...}
	
		if #arg == 0 then
			arg = nil
		end	

		self:send(
			Json.Encode({id, arg}).."\n"
		)
	end
	
	print ("accepted client ", info.ip, info.port)
	while true do
 		local data = client:receive()

		print ("Received from ", info.ip, info.port, " => ", data)
		
		if data == "quit" then
			break
		end
		
		local success, error = pcall(function()
			local msg = Json.Decode(line)
			local arg = msg[2]
	
			if msg[1] == MSG.INITSRV then
				--[id, hash, int:server_protocol_version]
				--if checkHash(hash, client.randomNumber, db.findKey(arg[1]) then
				client.authed = true
				--else
				--	client:disconnect()
				--end
				print ("client protocol version: " ..tostring(arg[3]))
			elseif client.authed and msg[1] == "" then
	
			else
				print "ignoring message id"
			end
		end)
		
		if not success then
			if type(error) == "string" then
				if DEBUG then
					client:sendCommand(MSG.ERROR, MSG.ERROR_ID.UNKOWN, error)
				else
					client:sendCommand(MSG.ERROR, MSG.ERROR_ID.UNKOWN, "Unkown error")
				end
			end
		end
	end
end


local server = socket.tcp()
assert(server:bind(ip, port))
assert(server:listen())

-- find out which port the OS chose for us
local RealIp, RealPort = server:getsockname()

-- print a message informing what's up
print("Please telnet to "..tostring(RealIp).." on port " .. tostring(RealPort))

--setup async clients
copas.addserver(server, clientHandler)

-- loop forever waiting for clients
while true do
	copas.step()
end


