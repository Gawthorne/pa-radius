# Palo Alto RADIUS

RADIUS accounting packet parser to Palo Alto User-to-IP mapping.

Receives accounting messages directly from a NAS (Switch, AP, etc) or forwarded from another RADIUS server.  
Decodes radius packet and pulls relevant information. Supports querying domain computers via WMI to get the currently logged on user.  
Once the user and IP has been discovered a GET request is sent directly to the Palo Alto Firewall using the PAN-OS XML API.

## Installation

This script has been wrote with [Node.js](https://nodejs.org) so you'll need to grab that.  
You will need to install `node-radius` and `wmi-client`. Both are available from npm which is bundled with Node.js. 
Assuming the location of npm is within your PATH, run the following commands in the same directory as pa-radius to install the dependancies:  
```
npm install radius
npm install wmi-client
```

Once they are both installed, modify the config template `config.js` to match your setup and launch pa-radius: `node pa-radius`

You can find more information about node-radius and wmi-client on their GitHub page:  
[node-radius](https://github.com/retailnext/node-radius)  
[wmi-client](https://github.com/R-Vision/wmi-client)  


