/******************************
RADIUS accounting packet parser to Palo Alto User-to-IP mapping.
Receives accounting messages directly from a NAS (Switch, AP, etc) or forwarded from another RADIUS server.
Decodes radius packet and pulls relevant information. Can be enabled to query domain computers via WMI to get the currently logged on user.
Once the user and IP has been discovered a GET request is sent directly to the Palo Alto Firewall using the PAN-OS XML API.

Author: Patrick Gawthorne

*******************************/

var radius = require('radius');
var dgram = require("dgram");
var querystring = require('querystring');
var https = require('https');
var WmiClient = require('wmi-client');
var config = require('./config');

var users = []; // Users array for throttling interim-updates
var reqNo = 0;

var server = dgram.createSocket("udp4");


function processRequest(type,username,ip,nas){
	switch(type){
		case 'Start': 
			// Send info to PA on every start RADIUS message
			reqNo++;
			mapUserIp(reqNo,username,ip, function(user,ip,id,lat){
				console.log('(%d) (%dms) %s from %s: %s %s',id,lat,type,nas,user,ip);
			});
			break;
		case 'Interim-Update':
			// Only parse every nth interim-update for each user.
			if(config.firewall.apiThrottle != 0){
				if(users[ip] == undefined || users[ip][0] != username)
					users[ip] = [username,config.firewall.apiThrottle];
				if(users[ip][1] < config.firewall.apiThrottle) {
					users[ip][1]++;
					var reqsLeft = config.firewall.apiThrottle - users[ip][1];
					//if(config.debug)
						console.log('Ignoring update request, will send after %d more requests: %s %s',reqsLeft,username,ip)
					break;
				}
			}
			reqNo++;
			mapUserIp(reqNo,username,ip, function(user,ip,id,lat){
				console.log('(%d) (%dms) %s from %s: %s %s',id,lat,type,nas,user,ip);
				if(config.firewall.apiThrottle != 0)
					users[ip][1] = 0;
			});
			break;
		case 'Stop':
			// Don't send any info to the Palo Alto firewall when receiving stop messages.
			// After the timeout configured in the GET request has passed, the IP to user mapping will clear.
			break;
		default:
			console.log('Status type not supported: ' + type);
	}
}
// returns username if user is not within ignored users list
function filterUser(username){
	//Strip and filter user
	let ignored = false;
	if(username != null){
		config.user.strip.forEach(word => {
			username = username.toLowerCase(); 
			username = username.replace(word, '');
		});
		config.user.ignored.forEach((v, k) => {
			if(username.indexOf(v) != -1){
				if(config.debug)
					console.log('User is in ignored users list: '+username);
				ignored = true;
				return;
			}
		});
	}
	return ignored || username;
}

function mapUserIp(id,user,ip,callback){
	var query = querystring.stringify({ 
		type: 'user-id',
		action: 'set',
		key: config.firewall.apiKey,
		cmd: '<uid-message>\n\
		<version>2.0</version>\n\
		<type>update</type>\n\
		<payload>\n\
		<login>\n\
		<entry name="'+config.user.domain+'\\'+user+'" ip="'+ip+'" timeout="'+config.user.timeout+'"/>\n\
		</login>\n\
		</payload>\n\
		</uid-message>'
	});
	var options = {
		host: config.firewall.host,
		path: '/api/?'+query
	};
	var time = Date.now();
	var req = https.get(options, function(res) {
		var buffer = "";
		res.on("data", function(data){
			buffer = buffer+data;
		});
		res.on("end", function(data){
			var latency = (Date.now()-time);
			if(res.statusCode == 200){
				if(buffer.indexOf('status="success"') != -1){
					callback(user,ip,id,latency);
				}else{
					console.log(id,'Firewall returned HTTP 200 however an error was thrown',user,ip);
					console.log(buffer);
				}
			}else{
				console.log(id, buffer);
			}
		});
	});
	// Set timeout to 6 minutes, a bandaid fix for a bug which seems to be in version 7.1.5
	req.setTimeout(360000,function () {
		console.log(new Date().toLocaleString(),' Request to firewall timed out:',user,ip,id);
		if(config.debug)
			console.log(req);
		req.abort();
		//console.log("\007");
	});
	req.on('error', function(e) {
		console.log('ERROR: ' + e.message);
	});
}

server.on("message", function (msg, rinfo){
	if(config.radius.nas.length > 0 && config.radius.nas.indexOf(rinfo.address) == -1){
		if(config.debug)
			console.log('Rejected accounting request from: %s',rinfo.address);
		return;
	}
	var username, packet, ip, mac, ap_ip;
	packet = radius.decode({packet: msg, secret: config.radius.secret});
	if(packet.code != 'Accounting-Request'){ // Ignore other RADIUS messages
		console.log('Unsupported packet type: ' + packet.code);
		return;
	}
	
	username = packet.attributes['User-Name'];
	ip = packet.attributes['Framed-IP-Address'];
	nas = packet.attributes['NAS-IP-Address'];
	mac = packet.attributes['Calling-Station-Id'];

	if(ip == undefined){
		if(config.debug)
			console.log('Client does not have a valid IP. Dropping request.',username, mac);
		return;
	}
	
	// Check if it's a machine account or not
	if(username.startsWith('host/')){
		if(config.wmi.enabled){
			var time = Date.now();
			// Send a WMI query to the machine and retrieve the logged in user - Drop request if user not logged in yet (UserName == NULL)
			var wmi = new WmiClient({
				username: config.wmi.username,
				password: config.wmi.password,
				host: ip
			});
			wmi.query('SELECT Username,Name FROM Win32_ComputerSystem', function (err, result) {
				if(err == null){
					var latency = (Date.now()-time);
					//console.log('(%dms) WMI query to %s resulted in: %s',latency,username,result[0]['UserName']);
					username = filterUser(result[0]['UserName']);
					if(typeof(username) == 'string'){
						processRequest(packet.attributes['Acct-Status-Type'],username,ip,nas);
					}
				}else{
					if(config.debug)
						console.log('WMI Query failed for machine %s. %s',username,err);
					return;
				}
			});
		}
	}else{
		username = filterUser(username);
		if(typeof(username) == 'string'){
			processRequest(packet.attributes['Acct-Status-Type'],username,ip,nas);
		}
	}
	// Prepare and send accounting response, even if the user was ignored.
	var response = radius.encode_response({
		packet: packet,
		code: 'Accounting-Response',
		secret: config.radius.secret
	});
	server.send(response, 0, response.length, rinfo.port, rinfo.address, function(err, bytes) {
		if (err) {
		  console.log('Error sending response to ', rinfo);
		}
	});
});

server.on("listening", function () {
	var address = server.address();
	console.log("PA RADIUS server listening "+address.address+":"+address.port);
});

server.bind(1813);
