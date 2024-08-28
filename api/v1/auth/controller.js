'use strict';

const rsmg = require('../../../response/rs');
const utils = require('../../../utils/utils');
const moment = require('moment');
const uuidv4 = require('uuid').v4;
const logger = require('../../../config/logger');
const formats = require('../../../config/format');
const mailer = require('../../../config/mailer');
const adrVerifikasi = require('../../../model/adr_verifikasi');
const adrAuth = require('../../../model/adr_auth');
const adrLogin = require('../../../model/adr_login');
const bcrypt = require('bcryptjs');
const saltRounds = 12;
const connectionDB = require('../../../config/db').Sequelize;
const axios = require('axios');
const {fire} = require("../../../config/firebase");
const firestore = fire.firestore();
const errMsg = require('../../../error/resError');
const ApiErrorMsg = require('../../../error/apiErrorMsg')
const HttpStatusCode = require("../../../error/httpStatusCode");
const nanoid = require('nanoid-esm')

exports.getLogin = async function (req, res) {
  try {
    const newDate = moment().format('YYYY-MM-DD HH:mm:ss')
    const kk = req.body.kk;
    const pin = req.body.pin;
    const deviceID = req.body.deviceID;
    let sessionLogin = uuidv4();
    sessionLogin = sessionLogin.replace(/-/g, "");

    if (formats.isEmpty(kk)) {
      throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90007');
    }
    if (formats.isEmpty(pin)) {
      throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90008');
    }
    if (formats.isEmpty(deviceID)) {
      throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90009');
    }
    
    const desiredLength = formats.generateRandomValue(15,20);
    const authRefresh = utils.shortID(desiredLength);

    const findVerif = await adrVerifikasi.findOne({
      raw: true,
      where: {
        kk: kk
      }
    })
    if (!findVerif) {
      return res.status(200).json(rsmg('90001', null));
    }

    if (findVerif && findVerif.is_registered == 1) {
      const account_id = findVerif.account_id;
      if (formats.isEmpty(account_id)) {
        return res.status(200).json(rsmg('90002', null));
      }

      const splitId = account_id.split('-');
      const splitIdLenght = splitId.length
      const partition = splitId[splitIdLenght - 1]

      const tabelLogin = adrLogin(partition)
      const dataAccountLogin = await tabelLogin.findOne({
        raw: true,
        where: {
          account_id: `${account_id}`
        }
      })
      if (!dataAccountLogin) {
        return res.status(200).json(rsmg('90002', null));
      }
      if (dataAccountLogin.blocked == 1) {
        throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90011');
      }

      if (dataAccountLogin.available_counter >= 3) {
        if (moment(newDate).isSameOrBefore(dataAccountLogin.next_available)) {
          throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90012', formats.getCurrentTimeInJakarta(dataAccountLogin.next_available));
        }

        await tabelLogin.update({
          modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
          modified_by: account_id,
          available_counter: null,
          next_available: null
        }, {
          where: {
            id: dataAccountLogin.id
          }
        })
      }

      const pinRegistered = dataAccountLogin.pin;
      const checkPin = await bcrypt.compare(pin, pinRegistered);
      if (checkPin) {
        let dataAccount = await axios({
          method: 'GET',
          url: process.env.MS_ACCOUNT_V1_URL + `/account/check/${account_id}`,
        });
        if (dataAccount.data.code != '000000' && dataAccount.data.data != true) {
          return res.status(200).json(rsmg('90001', null));
        }
        
        const payloadEnkripsiLogin = {
          id: dataAccountLogin.account_id,
          kk: kk,
          device_id: deviceID,
          partition: partition,
          organitation_id: findVerif.organitation_id,
          position_id: findVerif.position_id,
          sessionLogin: sessionLogin
        }
  
        const hash = await utils.enkrip(payloadEnkripsiLogin);        
        const token = await utils.signin(hash);

        const payloadEnkripsiRefresh = {
          id: dataAccountLogin.account_id,
          device_id: deviceID,
          authRefresh: authRefresh
        }
        const hashRefresh = await utils.enkripRefresh(payloadEnkripsiRefresh);        
        const tokenRefresh = await utils.signinRefresh(hashRefresh);

        await codeAuth(account_id, 'login', sessionLogin, authRefresh);

        await tabelLogin.update({
          modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
          modified_by: account_id,
          available_counter: null,
          next_available: null
        }, {
          where: {
            id: dataAccountLogin.id
          }
        })

        res.header('access-token', token);
        res.header('refresh-token', tokenRefresh);

        return res.status(200).json(rsmg('000000', {}));
      } else {
        let availCounter = dataAccountLogin.available_counter;
        availCounter = formats.isEmpty(availCounter) || parseInt(availCounter) >= 3 ? 0 : availCounter
        const newAvailCounter = parseInt(availCounter) + 1;
        const next_available = newAvailCounter == 3 ? moment(newDate).add(3, 'h').format('YYYY-MM-DD HH:mm:ss') : null;

        await tabelLogin.update({
          modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
          modified_by: account_id,
          available_counter: newAvailCounter,
          next_available: next_available
        }, {
          where: {
            id: dataAccountLogin.id
          }
        })

        if (newAvailCounter >= 3) {
          throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90012', formats.getCurrentTimeInJakarta(next_available));
        }
        throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90003');
      }
    } else {
      return res.status(200).json(rsmg('90002', null));
    }
  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/login...'})
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/login...', e);
  }
}

exports.getPreRegister = async function (req, res) {
  try {
    const kk = req.body.kk;

    const dataVerif = await adrVerifikasi.findOne({
      raw: true,
      where: {
        kk: kk
      }
    })

    if (!dataVerif) {
      return res.status(200).json(rsmg('90001', null));
    }

    if (dataVerif && dataVerif.is_registered == 1) {
      return res.status(200).json(rsmg('90004', null));
    }
    
    let dataMasterOrg = await axios({
      method: 'GET',
      url: process.env.MS_SUPPORT_V1_URL + `/master-organitation/${dataVerif.organitation_id}`
    })
    if (dataMasterOrg.data.code != '000000') {
      return res.status(200).json(dataMasterOrg.data);
    }

    let hasil = {
      dataAccount: dataVerif,
      dataOrg: dataMasterOrg.data.data
    }
    return res.status(200).json(rsmg('000000', hasil));
  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/pre-register...'});
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/pre-register...', e);
  }
}

exports.getPostRegister = async function (req, res) {
  let transaction = await connectionDB.transaction();
  try {
    const dateTime = moment().format('YYYY-MM-DD HH:mm:ss.SSS');
    const tabelRegistered = (await firestore.collection('daru').doc('register_partition').get()).data();
    const obj = tabelRegistered.partition.find(o => o.status);
    if (!obj) {
      throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90005');
    }
    const partition = obj.table;
    const tabelLogin = adrLogin(partition)

    const id = `${uuidv4()}-${partition}`;
    const nama = req.body.nama;
    const kk = req.body.kk
    const mobile_number = req.body.mobile_number;
    const email = req.body.email;
    const alamat = req.body.alamat;
    const blok = req.body.blok;
    const nomor_rumah = req.body.nomor_rumah;
    const rt = req.body.rt;
    const rw = req.body.rw;
    let pin = req.body.pin;
    pin = await bcrypt.hash(pin, saltRounds);

    const cekData = await connectionDB.query("SELECT * FROM adr_verifikasi WHERE kk = :kk_ FOR UPDATE",
    { replacements: { kk_: kk }, type: connectionDB.QueryTypes.SELECT, transaction: transaction },
    {
      raw: true
    });

    if (cekData.length > 0 && cekData[0].is_registered == 0) {
      await tabelLogin.create({
        id: uuidv4(),
        created_dt: dateTime,
        created_by: id,
        modified_dt: null,
        modified_by: null,
        is_deleted: 0,
        account_id: id,
        pin: pin,
        available_counter: null,
        next_available: null,
        blocked: 0,
      }, { transaction: transaction })

      await adrVerifikasi.update({
        account_id: id,
        is_registered: 1
      }, {
        where : {
          kk: cekData[0].kk
        },
        transaction: transaction
      })

      let hasilCreate = await axios({
        method: 'POST',
        url: process.env.MS_ACCOUNT_V1_URL + '/account/create-account',
        data: {
          partition: partition,
          dateTime: dateTime,
          id: id,
          nama: nama,
          kk: kk,
          mobile_number: mobile_number,
          email: email,
          alamat: alamat,
          blok: blok,
          nomor_rumah: nomor_rumah,
          rt: rt,
          rw: rw
        }
      })
      if (hasilCreate.data.code != "000000") {
        return res.status(200).json(hasilCreate.data);
      }

      await axios({
        method: 'POST',
        url: process.env.MS_PAYMENT_V1_URL + '/transaction/create-va',
        data: {
          id: id
        }
      })
      
      await transaction.commit();
      return res.status(200).json(rsmg('000000', {}));
    } else if (cekData.length > 0 && cekData[0].is_registered == 1) {
      await transaction.rollback();
      return res.status(200).json(rsmg('90004', null));
    } else {
      await transaction.rollback();
      return res.status(200).json(rsmg('90001', null));
    }
  } catch (e) {
    await transaction.rollback();
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/post-register...'});
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/post-register...', e);
  }
}

exports.verifyToken = async function(req, res){
  try{
    const token = req.headers['access-token'];
    if (!token) throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90006');

    const hasil = await newVerifyTokenMS(token);
    res.header('access-token', hasil.access_token);
    return res.status(200).json(rsmg('000000', hasil))
  }catch(e){
    logger.errorWithContext({ error: e, message: 'error GET /api/v1/auth/verify-token...'});
    return utils.returnErrorFunction(res, 'error POST GET /api/v1/auth/verify-token...', e);
  }
}

exports.verifyTokenSelft = async function(req, res, next){
  try{
    const token = req.headers['access-token'];
    if (!token) throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90006');

    const hasil = await newVerifyTokenMS(token);
    req.id = hasil.id;
    req.parts = hasil.partition;
    req.sessionLogin = hasil.sessionLogin;
    req.decrypt = hasil
    res.header('access-token', hasil.access_token);
    return next();
  }catch(e){
    logger.errorWithContext({ error: e, message: 'error verifyTokenSelft...'});
    return utils.returnErrorFunction(res, 'error verifyTokenSelft...', e);
  }
}

const newVerifyTokenMS = async function (token) {
  const verifyRes = await utils.verify(token);
  if (verifyRes.status == 400) {
    throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90013');
  } else if (verifyRes.status == 401){
    throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
  }
  const decrypt = await utils.dekrip(verifyRes.userToken.masterKey, verifyRes.userToken.buffer);

  const data = await adrAuth.findOne({
    raw: true,
    where: {
      account_id: decrypt.id,
      type: 'login'
    }
  })

  if (!data || (data.code !== decrypt.sessionLogin)) {
    throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
  }

  const newPayloadJWT = {
    id: decrypt.id,
    kk: decrypt.kk,
    device_id: decrypt.device_id,
    partition: decrypt.partition,
    organitation_id: decrypt.organitation_id,
    position_id: decrypt.position_id,
    sessionLogin: decrypt.sessionLogin
  };
  const hash = await utils.enkrip(newPayloadJWT);
  const newToken = await utils.signin(hash);

  const hasil = {
    ...newPayloadJWT,
    access_token: newToken
  }
  return hasil;
}

const verifyTokenMS = async function (token) {
  const verifyRes = await utils.verify(token);
  if (verifyRes.status == 400) {
    throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90013');
  } else if (verifyRes.status == 401){
    throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
  }
  const decrypt = await utils.dekrip(verifyRes.userToken.masterKey, verifyRes.userToken.buffer);
  const parts = decrypt.partition;
  const sessionLogin = decrypt.sessionLogin;

  const resAuth = await adrAuth.findOne({
    raw: true,
    where: {
      account_id: decrypt.id,
      type: 'login',
    },
  });
  
  if (!resAuth || resAuth?.validate != 1) {
    throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
  }

  const sessionKey = resAuth.code;
  if (sessionKey !== sessionLogin) {
    throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
  }

  const tabelLogin = adrLogin(parts)
  const resLogin = await tabelLogin.findOne({
    raw: true,
    where: {
      account_id: decrypt.id
    }
  })
  if (!resLogin || resLogin.blocked == 1) {
    throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
  }

  const newPayloadJWT = {
    id: decrypt.id,
    kk: decrypt.kk,
    device_id: decrypt.device_id,
    partition: decrypt.partition,
    organitation_id: decrypt.organitation_id,
    position_id: decrypt.position_id,
    sessionLogin: decrypt.sessionLogin
  };
  const hash = await utils.enkrip(newPayloadJWT);
  const newToken = await utils.signin(hash);

  const hasil = {
    ...newPayloadJWT,
    newToken: newToken
  }
  return hasil;
}

const codeAuth = async function (account_id, type, code, refreshToken = null) {
  let authRecord = await adrAuth.findOne({
    where: {
      account_id: account_id,
      type: type,
    },
  });

  if (!authRecord) {
    await adrAuth.create({
      id: uuidv4(),
      created_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
      created_by: account_id,
      modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
      modified_by: account_id,
      is_deleted: 0,
      account_id: account_id,
      code: code,
      type: type,
      validate: 1,
      refresh_token: refreshToken
    })
  } else {
    await adrAuth.update({
      modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
      modified_by: account_id,
      validate: 1,
      code: code,
      refresh_token: refreshToken
    }, {
      where: {
        id: authRecord.id
      }
    })
  }
}

exports.getLogout = async function (req, res) {
  try {
    const id = req.id;

    await adrAuth.update({
      modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
      modified_by: id,
      code: null,
      validate: 0
    }, {
      where: {
        account_id: id
      }
    })
      
    return res.status(200).json(rsmg('000000', {}))
  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error GET /api/v1/auth/logout...'});
    return utils.returnErrorFunction(res, 'error GET /api/v1/auth/logout...', e);
  }
}

exports.ubahPin = async function (req, res) {
  try {
    const id = req.id;
    const parts = req.parts
    let pin = req.body.pin;
    pin = await bcrypt.hash(pin, saltRounds);

    const tabelLogin = adrLogin(parts)
    await tabelLogin.update({
      pin: pin
    }, {
      where: {
        id: id
      }
    })

    return res.status(200).json(rsmg('000000'));
  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/ubah-pin...'});
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/ubah-pin...', e);
  }
}

exports.lupaPin = async function (req, res) {
  try {
    const kk = req.body.kk;
    let pin = req.body.pin;
    pin = await bcrypt.hash(pin, saltRounds);

    const findVerif = await adrVerifikasi.findOne({
      raw: true,
      where: {
        kk: kk
      }
    })
    if (!findVerif) {
      return res.status(200).json(rsmg('90001', null));
    }

    const account_id = findVerif.account_id;
    if (formats.isEmpty(account_id)) {
      return res.status(200).json(rsmg('90002', null));
    }

    const splitId = account_id.split('-');
    const splitIdLenght = splitId.length
    const partition = splitId[splitIdLenght - 1]

    const tabelLogin = adrLogin(partition)
    await tabelLogin.update({
      pin: pin,
      modified_dt: formats.getCurrentTimeInJakarta(moment().format('YYYY-MM-DD HH:mm:ss.SSS')),
      modified_by: account_id,
    }, {
      where: {
        account_id: account_id
      }
    })
    return res.status(200).json(rsmg('000000'));
  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/lupa-pin...' });
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/lupa-pin...', e);
  }
}

exports.refreshToken = async function (req, res) {
  try {
    const token = req.headers['refresh-token'];
    if (!token) throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90014');

    const verifyRes = await utils.verifyRefresh(token);
    const decrypt = await utils.dekripRefresh(verifyRes.masterKey, verifyRes.buffer);

    const account_id = decrypt.id;
    const auth_refresh = decrypt.authRefresh;
    const splitId = account_id.split('-');
    const splitIdLenght = splitId.length
    const partition = splitId[splitIdLenght - 1]

    
    const checkData = await adrAuth.findOne({
      raw: true,
      where: {
        account_id: account_id,
        type: 'login'
      }
    })

    if (!checkData) {
      throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
    }
    
    if (checkData.refresh_token !== auth_refresh) {
      throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
    }

    const dataAkun = await adrVerifikasi.findOne({
      raw: true,
      where: {
        account_id: account_id,
      }
    })

    if (!dataAkun) {
      throw new ApiErrorMsg(HttpStatusCode.UNAUTHORIZED, '90010');
    }

    const desiredLength = formats.generateRandomValue(15,20);
    const authRefresh = utils.shortID(desiredLength);

    const payloadEnkripsiLogin = {
      id: decrypt.id,
      kk: dataAkun.kk,
      device_id: decrypt.device_id,
      partition: partition,
      organitation_id: dataAkun.organitation_id,
      position_id: dataAkun.position_id,
      sessionLogin: checkData.code
    }
    const hash = await utils.enkrip(payloadEnkripsiLogin);        
    const newAccessToken = await utils.signin(hash);

    const payloadEnkripsiRefresh = {
      id: account_id,
      device_id: decrypt.device_id,
      authRefresh: authRefresh
    }
    const hashRefresh = await utils.enkripRefresh(payloadEnkripsiRefresh);        
    const tokenRefresh = await utils.signinRefresh(hashRefresh);

    await codeAuth(account_id, 'login', checkData.code, authRefresh);

    return res.status(200).json(rsmg('000000', {
      access_token: newAccessToken,
      refresh_token: tokenRefresh
    }));
  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/refresh-token...' });
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/refresh-token...', e);
  }
}

exports.verifyPin = async function (req, res) {
  try {
    const code = nanoid(10);
    const newDate = moment().format('YYYY-MM-DD HH:mm:ss')
    const id = req.id;
    const type = req.body.type;
    const pin = req.body.pin;

    const splitId = id.split('-');
    const splitIdLenght = splitId.length
    const partition = splitId[splitIdLenght - 1]

    const tabelLogin = adrLogin(partition)
    const dataAccountLogin = await tabelLogin.findOne({
      raw: true,
      where: {
        account_id: id
      }
    })
    if (!dataAccountLogin) {
      throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90003');
    }
    if (dataAccountLogin.blocked == 1) {
      throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90011');
    }

    if (dataAccountLogin.available_counter >= 3) {
      if (moment(newDate).isSameOrBefore(dataAccountLogin.next_available)) {
        throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90012', formats.getCurrentTimeInJakarta(dataAccountLogin.next_available));
      }

      await tabelLogin.update({
        modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
        modified_by: id,
        available_counter: null,
        next_available: null
      }, {
        where: {
          id: dataAccountLogin.id
        }
      })
    }

    const pinRegistered = dataAccountLogin.pin;
    const checkPin = await bcrypt.compare(pin, pinRegistered);
    if (checkPin) {
      if (type === 'tfp') {
        await codeAuth(id, type, code);
      }

      await tabelLogin.update({
        modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
        modified_by: id,
        available_counter: null,
        next_available: null
      }, {
        where: {
          id: dataAccountLogin.id
        }
      })

      return res.status(200).json(rsmg('000000', {
        type: type,
        code: code
      }));
    } else {
      let availCounter = dataAccountLogin.available_counter;
      availCounter = formats.isEmpty(availCounter) || parseInt(availCounter) >= 3 ? 0 : availCounter
      const newAvailCounter = parseInt(availCounter) + 1;
      const next_available = newAvailCounter == 3 ? moment(newDate).add(3, 'h').format('YYYY-MM-DD HH:mm:ss') : null;

      await tabelLogin.update({
        modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
        modified_by: id,
        available_counter: newAvailCounter,
        next_available: next_available
      }, {
        where: {
          id: dataAccountLogin.id
        }
      })

      if (newAvailCounter >= 3) {
        throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90012', formats.getCurrentTimeInJakarta(next_available));
      }
      throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90003');
    }

  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/verify-pin...' });
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/verify-pin...', e);
  }
}

exports.verifyCodeTrx = async function (req, res) {
  try {
    const type = req.body.type;
    const code = req.body.code;
    const id = req.id;

    const check = await adrAuth.findOne({
      raw: true,
      where: {
        account_id: id,
        type: type,
        code: code
      }
    })

    if (!check) {
      throw new ApiErrorMsg(HttpStatusCode.BAD_REQUEST, '90015');
    }

    await adrAuth.destroy({
      where: { id: check.id }
    });

    return res.status(200).json(rsmg('000000'))
  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/verify-code-trx...' });
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/verify-code-trx...', e);
  }
}