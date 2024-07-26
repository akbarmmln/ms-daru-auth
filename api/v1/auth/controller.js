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

exports.getLogin = async function (req, res) {
  try {
    const kk = req.body.kk;
    const pin = req.body.pin;
    const deviceID = req.body.deviceID;

    if (formats.isEmpty(kk)) {
      throw '90007'
    }
    if (formats.isEmpty(pin)) {
      throw '90008'
    }
    if (formats.isEmpty(deviceID)) {
      throw '90009'
    }
    
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
      const pinRegistered = dataAccountLogin.pin;
      const checkPin = await bcrypt.compare(pin, pinRegistered);
      if (checkPin) {
        let dataAccount = await axios({
          method: 'GET',
          url: process.env.MS_ACCOUNT_V1_URL + `/account/${account_id}`,
        });
        if (dataAccount.data.code != '000000' && dataAccount.data.data != true) {
          return res.status(200).json(rsmg('90001', null));
        }
        
        const payloadEnkripsiLogin = {
          id: dataAccountLogin.account_id,
          kk: kk,
          device_id: deviceID
        }
  
        const hash = await utils.enkrip(payloadEnkripsiLogin);
        const sessionKey = hash.secretKey;
        const validHash = {
          buffer: hash.buffer,
          masterKey: hash.masterKey    
        }
        const token = await utils.signin(validHash);
  
        await codeAuth(account_id, 'login', sessionKey);

        res.set('Access-Control-Expose-Headers', 'access-token');
        res.set('access-token', token);
  
        return res.status(200).json(rsmg('000000', {}));
      } else {
        throw '90003'
      }
    } else {
      return res.status(200).json(rsmg('90002', null));
    }
  } catch (e) {
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth...'})
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth...', e);
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

exports.getPostReister = async function (req, res) {
  let transaction = await connectionDB.transaction();
  try {
    const dateTime = moment().format('YYYY-MM-DD HH:mm:ss.SSS');
    const tabelRegistered = (await firestore.collection('daru').doc('register_partition').get()).data();
    const obj = tabelRegistered.partition.find(o => o.status);
    if (!obj) {
      throw '90005';
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
    let token = req.headers['access-token'];
    if (!token) return res.status(401).json(errMsg('90006'));

    let verifyRes = await utils.verify(token);
    let decrypt = await utils.dekrip(verifyRes.masterKey, verifyRes.buffer);
    logger.infoWithContext(`hasil decrypt ${JSON.stringify(decrypt)}`);

    const resAuth = await adrAuth.findOne({
      where: {
        account_id: decrypt.id,
        type: 'login',
      },
    });
    console.log(`kok masuk sini ${JSON.stringify(resAuth)}`)
    if (!resAuth) {
      console.log('kok masuk sini1')
      return res.status(401).json(errMsg('90010'));
    }
    if (resAuth?.validate != 1) {
      console.log('kok masuk sini2')
      return res.status(401).json(errMsg('90010'));
    }

    const sessionKey = resAuth.code;
    if (sessionKey !== decrypt.dcs) {
      return res.status(401).json(errMsg('90010'));
    }

    const newPayloadJWT = {
      id: decrypt.id,
      kk: decrypt.kk,
      device_id: decrypt.device_id
    };

    const signJWT = await utils.enkrip(newPayloadJWT);
    const newToken = await utils.signin(signJWT);

    const hasil = {
      id: decrypt.id,
      kk: decrypt.kk,
      device_id: decrypt.device_id,
      newToken: newToken
    }
    return res.status(200).json(rsmg('000000', hasil))
  }catch(e){
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/verify-token...'});
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/verify-token...', e);
  }
}

const codeAuth = async function (account_id, type, code) {
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
    })
  } else {
    await adrAuth.update({
      modified_dt: moment().format('YYYY-MM-DD HH:mm:ss.SSS'),
      modified_by: account_id,
      validate: 1,
      code: code,
    }, {
      where: {
        id: authRecord.id
      }
    })
  }
}

exports.getLogout = async function (req, res) {
  try {
    const id = req.body.id;

    await adrAuth.update({
      modified_dt: null,
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
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/logout...'});
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/logout...', e);
  }
}