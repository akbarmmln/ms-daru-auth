const moment = require('moment');
const errCode = require('./errCode');
const format = require('../config/format');

function resError(code, e, messageErr = '') {
  let messageCode = errCode[code];
  return {
    message: 'unsuccessful',
    err_code: code,
    err_msg: format.isEmpty(messageCode) ? messageErr : messageCode,
    err_msg2: e,
    language: 'EN',
    timestamp: format.getCurrentTimeInJakarta(moment().format())
  }
}

module.exports = resError;