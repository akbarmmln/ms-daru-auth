/* eslint-disable func-names */
const logger = require('./logger');
const { asyncLocalStorage } = require('./context');

// eslint-disable-next-line import/order
const httpLogger = require('pino-http')({
  // Reuse an existing logger instance
  logger: logger.get(),

  // Define a custom logger level
  customLogLevel: function (req, res, err) {
    if (res.statusCode >= 400 && res.statusCode < 500) {
      return 'warn';
    } else if (res.statusCode >= 500 || err) {
      return 'error';
    } else if (res.statusCode >= 300 && res.statusCode < 400) {
      return 'debug';
    }
    return 'info';
  },

  customErrorMessage(req) {
    return {
      id: req.headers['x-request-id'],
      message: 'Request failed',
    };
  },

  customSuccessMessage(req) {
    return {
      id: req.headers['x-request-id'],
      message: 'Request completed',
    };
  },

  customAttributeKeys: {
    req: 'request',
    res: 'response',
  },

  serializers: {
    req(req) {
      delete req.headers;
      req.body = req.raw.body;
      req.id = req.headers?.['x-request-id'] || '';

      return req;
    },
    res(res) {
      delete res.headers;
      res.body = res.raw.body;
      return res;
    },
    error(err) {
      delete err.type;
      err.stack = getStackTrace(err.stack);

      return err;
    },
  },
  customSuccessObject: (req, res, val) => {
    return {
      module: process.env.SERVICE_NAME,
      custom_attributes: {
        response: val.response.body,
        statusCode: val.response.statusCode,
        statusMessage: val.response.statusMessage,
        responseTime: val.responseTime,
      },
      err: {}
    };
  },

  customErrorObject: (req, res, error, val) => {
    return {
      module: process.env.SERVICE_NAME,
      custom_attributes: {
        response: val.response.body,
        statusCode: val.response.statusCode,
        statusMessage: val.response.statusMessage,
        responseTime: val.responseTime,
      },
      err: val.err
    };
  },
});

const integrationAttachResponseBody = function (req, res, next) {
  const { send } = res;
  res.send = function (body) {
    res.body = body;
    send.call(this, body);
  };
  next();
};

const integrationAttachContext = function (req, res, next) {
  const data = asyncLocalStorage.getStore().get('context');
  req.context = asyncLocalStorage.getStore().get('context');
  logger.setContext(data);
  req.headers['x-request-id'] = data['x-request-id'];
  httpLogger(req, res);
  next();
};

const getStackTrace = function (error) {
  if (!error) {
    return [];
  }
  const stackTrace = [];

  error
    .split('\n')
    .slice(1)
    .map((r) => r.match(/\((?<file>.*):(?<line>\d+):(?<pos>\d+)\)/))
    .forEach((r) => {
      if (!r?.groups?.file.match(/internal|node\:/)) {
        // exclude internal node module
        if (r?.groups?.file) {
          stackTrace.push(`${r.groups.file} line ${r.groups.line} pos ${r.groups.pos}`);
        }
      }
    });

  return stackTrace;
};

module.exports = {
  httpLogger,
  integrationAttachResponseBody,
  integrationAttachContext,
};
