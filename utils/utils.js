const logger = require('../config/logger');
const errMsg = require('../error/resError');
const crypto = require('node:crypto');
const uuidv4 = require('uuid').v4;
const jwt = require('jsonwebtoken');

exports.returnErrorFunction = function (resObject, errorMessageLogger, errorObject) {
  if (typeof errorObject === 'string') {
    logger.error(errorMessageLogger, errorObject);
    return resObject.status(400).json(errMsg(errorObject));
  } else if (errorObject.error) {
    logger.error(errorObject.error.err_code, errorObject);
    return resObject.status(500).json(errorObject.error);
  } else {
    logger.error(errorObject);
    return resObject.status(500).json(errMsg('10000'));
  }
};

exports.enkrip = async function (payload) {
  try {
    const publickEncrypt = process.env.PUBLIC_KEY_GCM;
    let secretKey = uuidv4();
    secretKey = secretKey.replace(/-/g, "");

    const bodyKey = JSON.stringify(payload);
    const bodyString = bodyKey.replace(/ /gi, '');

    let encs = crypto.publicEncrypt(
      {
        key: publickEncrypt.replace(/\\n/gm, '\n'),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      }, Buffer.from(secretKey));
    encs = encs.toString("base64");

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(bodyString, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      buffer: Buffer.concat([encrypted, tag, iv]).toString('base64'),
      masterKey: encs
    }
  } catch (e) {
    logger.error('error function enkrip...', e);
    throw e
  }
}

exports.signin = async function (hash) {
  try {
    const secret = require('../setting').secret;
    const privateKey = process.env.PRIVATE_KEY_JWT;

    const options = {
      issuer: 'daruku',
      algorithm: 'RS256'
    };
    const token = jwt.sign(
      hash,
      { key: privateKey.replace(/\\n/gm, '\n'), passphrase: secret },
      options,
    );
    return token;
  } catch (e) {
    logger.error('error function signin...', e);
    throw e
  }
}

exports.verify = async function (token) {
  try {
    const publicKey = process.env.PUBLIC_KEY_JWT;

    const options = {
      issuer: 'adiraku',
      algorithms: ['RS256']
    };

    const userToken = jwt.verify(
      token,
      publicKey.replace(/\\n/gm, '\n'),
      options
    );
    return userToken;
  } catch (e) {
    logger.error('error function verify...', e);
    throw e
  }
}

exports.dekrip = async function (masterkey, data) {
  try {
    const privateDecrypt = process.env.PRIVATE_KEY_GCM;

    let options = {
      key: privateDecrypt.replace(/\\n/gm, '\n'),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    };
    let dcs = crypto.privateDecrypt(options, Buffer.from(masterkey, "base64"));
    dcs = dcs.toString("utf8");

    const bufferData = Buffer.from(data, 'base64');
    const iv = Buffer.from(bufferData.slice(bufferData.length - 12, bufferData.length));
    const tag = Buffer.from(bufferData.slice(bufferData.length - 28, bufferData.length - 12));
    let cipherByte = Buffer.from(bufferData.slice(0, bufferData.length - 28));

    const decipher = crypto.createDecipheriv('aes-256-gcm', dcs, iv);
    decipher.setAuthTag(tag);

    let result = Buffer.concat([decipher.update(cipherByte), decipher.final()]);
    result = JSON.parse(result.toString())
    return result
  } catch (e) {
    logger.error('error function dekrip...', e);
    throw e
  }
}