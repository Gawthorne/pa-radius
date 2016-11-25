var config = {};

config.firewall = {};
config.radius = {};
config.user = {};
config.wmi = {};
config.log = {};

config.firewall.host = process.env.PAR_HOST || 'hostnameorip';
config.firewall.apiKey = process.env.PAR_API_KEY || 'apikey';

config.wmi.enabled = true;
config.wmi.username = process.env.PAR_USER || 'username'; 
config.wmi.password = process.env.PAR_PASS || 'password';

// Parse every nth interim-update for each user.
// Each user has it's own counter. Set 0 to disable.
config.firewall.apiThrottle = 0;

config.radius.secret = process.env.PAR_SECRET || 'secret';
// Add your NAS's here (Where the accounting messages are coming from, switch, AP, RADIUS server, etc)
// Leave empty to disable IP check
config.radius.nas = process.env.PAR_NAS || [];

config.user.timeout = 120;
config.user.ignored = (process.env.PAR_IGNORED.split(',').length > 0) ? process.env.PAR_IGNORED.split(',') : [];
config.user.strip = (process.env.PAR_STRIP.split(',').length > 0) ? process.env.PAR_STRIP.split(',') : [];
config.user.domain = process.env.PAR_DOMAIN || '';

// Logging levels are: { error: 0, warn: 1, info: 2, verbose: 3, debug: 4, silly: 5 }

config.log.level = 'info';
config.log.file = 'pa-radius.log';

//Ignore certificate errors. Comment line out if using a valid certificate.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";


module.exports = config;
