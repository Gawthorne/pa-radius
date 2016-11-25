# Palo Alto RADIUS

RADIUS accounting packet parser to Palo Alto User-to-IP mapping.

Receives accounting messages directly from a NAS (Switch, AP, etc) or forwarded from another RADIUS server.  
Decodes the RADIUS accounting packet and grabs user information. Once the user and IP has been discovered a  
GET request is sent directly to the Palo Alto Firewall using the PAN-OS XML API.

Supports querying domain computers via WMI to get the currently logged on user.  

## Installation

This script has been wrote with [Node.js](https://nodejs.org) so you'll need to grab that.  
You will need to install three dependancies. All are available from npm which is bundled with Node.js.  
Assuming the location of npm is within your PATH, run the following commands in the same directory as pa-radius to install the dependancies:  
```
npm install radius wmi-client winston
```

Modify the config template `config.js` before running.  
To run `pa-radius`, run `node pa-radius` while in it's directory.

You can also find more info about the dependancies on their GitHub pages:  
* [node-radius](https://github.com/retailnext/node-radius)  
* [wmi-client](https://github.com/R-Vision/wmi-client)  
* [winston](https://github.com/winstonjs/winston)


