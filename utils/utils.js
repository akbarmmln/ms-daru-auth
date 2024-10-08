const logger = require('../config/logger');
const errMsg = require('../error/resError');
const crypto = require('node:crypto');
const uuidv4 = require('uuid').v4;
const jwt = require('jsonwebtoken');
const BaseError = require('../error/baseError');
const shortUuid = require('short-uuid');

exports.returnErrorFunction = function (resObject, errorMessageLogger, errorObject) {
  if (errorObject instanceof BaseError) {
    return resObject.status(errorObject.statusCode).json(errMsg(errorObject.errorCode, errorObject.description, errorObject?.errorDetails));
  } else {
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
    logger.errorWithContext({message: 'error function enkrip...', error: e});
    throw e
  }
}

exports.signin = async function (hash) {
  try {
    const secret = require('../setting').secret;
    const privateKey = process.env.PRIVATE_KEY_JWT;

    const options = {
      issuer: 'daruku',
      algorithm: 'RS256',
      expiresIn: 3600,
    };
    const token = jwt.sign(
      hash,
      { key: privateKey.replace(/\\n/gm, '\n'), passphrase: secret },
      options,
    );
    return token;
  } catch (e) {
    logger.errorWithContext({message: 'error function signin...', error: e});
    throw e
  }
}

exports.verify = async function (token) {
  try {
    const publicKey = process.env.PUBLIC_KEY_JWT;

    const options = {
      issuer: 'daruku',
      algorithms: ['RS256']
    };

    const userToken = jwt.verify(
      token,
      publicKey.replace(/\\n/gm, '\n'),
      options
    );
    return {
      status: 200,
      userToken: userToken
    };
  } catch (e) {
    if (e?.name == 'TokenExpiredError') {
      return {
        status: 400,
        userToken: null
      };
    } else {
      return {
        status: 401,
        userToken: null
      };
    }
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
    return {
      ...result,
      dcs
    }
  } catch (e) {
    logger.errorWithContext({message: 'error function dekrip...', error: e});
    throw e
  }
}

exports.shortID = function (length) {
  const customAlphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const translator = shortUuid(customAlphabet);
  const shortId = translator.new();

  if (length) {
    return shortId.slice(0, length).padEnd(length, customAlphabet.charAt(0));
  }
  return shortId;
}

exports.enkripRefresh = async function (payload) {
  try {
    const publickEncrypt = process.env.PUBLIC_KEY_GCM_REFRESH;
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
    logger.errorWithContext({message: 'error function enkrip refresh...', error: e});
    throw e
  }
}

exports.signinRefresh = async function (hash) {
  try {
    const secret = require('../setting').secret_refresh;
    const privateKey = process.env.PRIVATE_KEY_JWT_REFRESH;

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
    logger.errorWithContext({message: 'error function signin refresh...', error: e});
    throw e
  }
}

exports.verifyRefresh = async function (token) {
  try {
    const publicKey = process.env.PUBLIC_KEY_JWT_REFRESH;

    const options = {
      issuer: 'daruku',
      algorithms: ['RS256'],
    };

    const userToken = jwt.verify(
      token,
      publicKey.replace(/\\n/gm, '\n'),
      options
    );

    return userToken;
  } catch (e) {
    logger.errorWithContext({message: 'error function verify refresh...', error: e});
    throw e
  }
}

exports.dekripRefresh = async function (masterkey, data) {
  try {
    const privateDecrypt = process.env.PRIVATE_KEY_GCM_REFRESH;

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
    return {
      ...result,
      dcs
    }
  } catch (e) {
    logger.errorWithContext({message: 'error function dekrip refresh...', error: e});
    throw e
  }
}