'use strict';
require('dotenv').config();
const app = require('./app');
const logger = require('./config/logger');

// Constants
let PORT = process.env.PORT

const server = app.listen(PORT, () => logger.infoWithContext(`API Server started. Listening on port:${PORT}`));
// mqttConfig.mqtt();

module.exports = server;