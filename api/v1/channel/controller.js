const jwt = require('jsonwebtoken');
const logger = require('../../../config/logger');
const rsMsg = require('../../../response/rs');
const errMsg = require('../../../error/resError');
const crypto = require('node:crypto');
const utils = require('../../../utils/utils');

exports.verifyAndDekripToken = async function(req, res){
	try{
		const publicKey = process.env.PUBLIC_KEY_JWT;
		let accessToken = req.headers['access-token'];
		
		const optionsJWT = {
			issuer: 'daruku',
			algorithms: ['RS256']
		};
		const userToken = jwt.verify(
			accessToken,
			publicKey.replace(/\\n/gm, '\n'),
			optionsJWT
		);
		
		const privateDecrypt = process.env.PRIVATE_KEY_GCM;
		const masterkey = userToken.masterKey
		const data = userToken.buffer

		let options = {
			key: privateDecrypt.replace(/\\n/gm, '\n'),
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: "sha256"
		};
		let dcs = crypto.privateDecrypt(options, Buffer.from(masterkey, "base64"));
		dcs = dcs.toString("utf8");

		const bufferData = Buffer.from(data, 'base64');
		const iv = Buffer.from(bufferData.slice(bufferData.length - 12, bufferData.length));
		const tag = Buffer.from(bufferData.slice(bufferData.length-28, bufferData.length-12));
		let cipherByte = Buffer.from(bufferData.slice(0, bufferData.length - 28));
	
		const decipher = crypto.createDecipheriv('aes-256-gcm', dcs, iv);
		decipher.setAuthTag(tag);
	
		let result = Buffer.concat([decipher.update(cipherByte), decipher.final()]);
		result = JSON.parse(result.toString())
		return res.status(200).json(rsMsg("000000", result))
	}catch(e){
        logger.errorWithContext({ error: e, message: 'error POST /api/v1/channel/verify-dekrip-token...'})
        return utils.returnErrorFunction(res, 'error POST /api/v1/channel/verify-dekrip-token...', e);
	}
}

exports.verifyAndDekripTokenRefresh = async function(req, res){
	try{
		const publicKey = process.env.PUBLIC_KEY_JWT_REFRESH;
		let refreshToken = req.headers['refresh-token'];
		
		const optionsJWT = {
			issuer: 'daruku',
			algorithms: ['RS256']
		};
		const userToken = jwt.verify(
			refreshToken,
			publicKey.replace(/\\n/gm, '\n'),
			optionsJWT
		);
		
		const privateDecrypt = process.env.PRIVATE_KEY_GCM_REFRESH;
		const masterkey = userToken.masterKey
		const data = userToken.buffer

		let options = {
			key: privateDecrypt.replace(/\\n/gm, '\n'),
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: "sha256"
		};
		let dcs = crypto.privateDecrypt(options, Buffer.from(masterkey, "base64"));
		dcs = dcs.toString("utf8");

		const bufferData = Buffer.from(data, 'base64');
		const iv = Buffer.from(bufferData.slice(bufferData.length - 12, bufferData.length));
		const tag = Buffer.from(bufferData.slice(bufferData.length-28, bufferData.length-12));
		let cipherByte = Buffer.from(bufferData.slice(0, bufferData.length - 28));
	
		const decipher = crypto.createDecipheriv('aes-256-gcm', dcs, iv);
		decipher.setAuthTag(tag);
	
		let result = Buffer.concat([decipher.update(cipherByte), decipher.final()]);
		result = JSON.parse(result.toString())
		return res.status(200).json(rsMsg("000000", result))
	}catch(e){
        logger.errorWithContext({ error: e, message: 'error POST /api/v1/channel/verify-dekrip-token-refresh...'})
        return utils.returnErrorFunction(res, 'error POST /api/v1/channel/verify-dekrip-token-refresh...', e);
	}
}