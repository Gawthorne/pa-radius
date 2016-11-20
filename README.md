# Palo Alto RADIUS

RADIUS accounting packet parser to Palo Alto User-to-IP mapping.
Receives accounting messages directly from a NAS (Switch, AP, etc) or forwarded from another RADIUS server.
Decodes radius packet and pulls relevant information. Sends a GET request directly to the Palo Alto Firewall using the PAN-OS XML API.

To use node-radius needs to be installed. `npm install radius` (https://github.com/retailnext/node-radius)
Modify the config template `config.js` to match your setup
