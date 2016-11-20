/******************************
RADIUS accounting packet parser to Palo Alto User-to-IP mapping.
Receives accounting messages directly from a NAS (Switch, AP, etc) or forwarded from another RADIUS server.
Decodes radius packet and pulls relevant information. Sends a GET request directly to the Palo Alto Firewall using the PAN-OS XML API.

Author: Patrick Gawthorne

*******************************/

var radius = require('radius');
var dgram = require("dgram");
var querystring = require('querystring');
var https = require('https');
var config = require('./config');

var users = []; // Users array for throttling interim-updates
var reqNo = 0;

var server = dgram.createSocket("udp4");

function mapUserIp(user,ip,callback){
	reqNo++;
	var query = querystring.stringify({ 
		type: 'user-id',
		action: 'set',
		key: config.firewall.apiKey,
		cmd: '<uid-message><version>2.0</version><type>update</type><payload><login><entry name="'+config.user.domain+'\\'+user+'" ip="'+ip+'" timeout="'+config.user.timeout+'"></entry></login></payload></uid-message>'
	});
	var options = {
		host: config.firewall.host,
		path: '/api/?'+query
	};
	var req = https.get(options, function(res) {
		var buffer = "";
		res.on("data", function(data){
			buffer = buffer+data;
		});
		res.on("end", function(data){
			if(res.statusCode == 200){
				if(buffer.indexOf('status="success"') != -1){
					callback(res.statusCode,user,ip,reqNo);
				}else{
					console.log(reqNo,'Firewall returned 200 but was not successful',user,ip);
					console.log(buffer);
				}
			}else{
				console.log(reqNo, buffer);
			}
		});
	});
	req.setTimeout(2000,function () {
		req.abort();
		console.log("\007");
		console.log(new Date().toLocaleString(),' Request to firewall timed out:',user,ip,reqNo);
	});
	req.on('error', function(e) {
		console.log('ERROR: ' + e.message);
	});
}

server.on("message", function (msg, rinfo){
	var username, packet, ip, mac, ap_ip;
	packet = radius.decode({packet: msg, secret: config.radius.secret});
	
	if(packet.code != 'Accounting-Request'){ // Ignore other RADIUS messages
		console.log('Unsupported packet type: ' + packet.code);
		return;
	}
	
	username = packet.attributes['User-Name'];
	ip = packet.attributes['Framed-IP-Address'];
	ap_ip = packet.attributes['NAS-IP-Address'];
	mac = packet.attributes['Calling-Station-Id'];

	if(ip == undefined){
		console.log('Client does not have a valid IP. Dropping request.',username, mac);
		return;
	}
	
	//Strip and filter user
	let ignored = false;
	config.user.strip.forEach(word => {
		username = username.toLowerCase(); 
		username = username.replace(word, '');
	});
	config.user.ignored.forEach((v, k) => {
		if(username.indexOf(v) != -1){
			console.log('User is in ignored users list: '+username);
			ignored = true;
			return;
		}
	});
	
	if(!ignored){
		switch(packet.attributes['Acct-Status-Type']){
			case 'Start': 
				// Send info to PA on every start RADIUS message
				mapUserIp(username,ip, function(code,user,ip,id){
					console.log(id+' (Response: '+code+') '+packet.attributes['Acct-Status-Type']+' from '+ap_ip+': '+user,ip);
				});
				break;
			
			case 'Interim-Update':
				// Only parse every nth interim-update for each user.
				if(config.firewall.apiThrottle != 0){
					if(users[ip] == undefined)
						users[ip] = [username,0];
					if(users[ip][1] < 10) {
						users[ip][1]++;
						//console.log('Ignoring update request, will send after '+(10 - users[ip][1])+' more requests.',username,ip);
						break;
					}
				}
				mapUserIp(username,ip, function(code,user,ip,id){
					console.log(id+' (Response: '+code+') '+packet.attributes['Acct-Status-Type']+' from '+ap_ip+': '+user,ip);
					if(config.firewall.apiThrottle != 0)
						users[ip][1] = 0;
				});
				break;
				
			case 'Stop':
				// Don't send any info to the Palo Alto firewall when receiving stop messages.
				// After the timeout configured in the GET request has passed, the IP to user mapping will clear.
				break;
			default:
				console.log('Status type not supported: ' + packet.attributes['Acct-Status-Type']);
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
	console.log("PA Radius server listening "+address.address+":"+address.port);
});

server.bind(1813);
