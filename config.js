var config = {};

config.firewall = {};
config.radius = {};
config.user = {};


config.firewall.host = process.env.PAR_HOST || 'hostnameorip';
config.firewall.apiKey = process.env.PAR_API_KEY || 'apikey';

// Parse every nth interim-update for each user.
// Each user has it's own counter. Set 0 to disable.
config.firewall.apiThrottle = 0;

config.radius.secret = process.env.PAR_SECRET || 'secret';

config.user.timeout = 120;
config.user.ignored = (process.env.PAR_IGNORED.split(',').length > 0) ? process.env.PAR_IGNORED.split(',') : [];
config.user.strip = (process.env.PAR_STRIP.split(',').length > 0) ? process.env.PAR_STRIP.split(',') : [];
config.user.domain = process.env.PAR_DOMAIN || '';

//Ignore certificate errors. Comment line out if using a valid certificate.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

//Enable debug messages (ignored users, invalid IP's, HTTP responses)
config.debug = false;

module.exports = config;