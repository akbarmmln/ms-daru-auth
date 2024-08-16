const moment = require('moment');
const errCode = require('./errCode');
const format = require('../config/format');

function resError(code, description, errorDetails = '') {
  return {
    message: 'unsuccessful',
    err_code: code,
    err_msg: description,
    err_msg2: errorDetails,
    language: 'EN',
    timestamp: format.getCurrentTimeInJakarta(moment().format())
  }
}

module.exports = resError;