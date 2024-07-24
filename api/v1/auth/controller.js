'use strict';

const rsmg = require('../../../response/rs');
const utils = require('../../../utils/utils');
const moment = require('moment');
const uuidv4 = require('uuid').v4;
const logger = require('../../../config/logger');
const formats = require('../../../config/format');
const mailer = require('../../../config/mailer');
const adrVerifikasi = require('../../../model/adr_verifikasi');
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

      let dataAccount = await axios({
        method: 'GET',
        url: process.env.MS_ACCOUNT_URL + `/api/v1/account/${account_id}`,
      });
      if (dataAccount.data.code != '000000' && dataAccount.data.data != true) {
        return res.status(200).json(rsmg('90001', null));
      }

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

      const payloadEnkripsiLogin = {
        id: dataAccountLogin.account_id,
        kk: kk
      }
      const pinRegistered = dataAccountLogin.pin;
      const checkPin = await bcrypt.compare(pin, pinRegistered);

      if (checkPin) {
        const hash = await utils.enkrip(payloadEnkripsiLogin);
        const token = await utils.signin(hash);
  
        res.set('Access-Control-Expose-Headers', 'access-token');
        res.set('access-token', token);
  
        return res.status(200).json(rsmg('000000', null));
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
      url: process.env.MS_SUPPORT_URL + `/api/v1/master-organitation/${dataVerif.organitation_id}`
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
        url: process.env.MS_ACCOUNT_URL + '/api/v1/account/create-account',
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
    if (!token) return res.status(403).json(errMsg('90006'));

    let verifyRes = await utils.verify(token);
    let decrypt = await utils.dekrip(verifyRes.masterKey, verifyRes.buffer);

    let newPayloadJWT = {
      id: decrypt.id,
      kk: decrypt.kk,
    };

    let signJWT = await utils.enkrip(newPayloadJWT);
    let newToken = await utils.signin(signJWT);

    let hasil = {
      id: decrypt.id,
      newToken: newToken
    }
    return res.status(200).json(rsmg('000000', hasil))
  }catch(e){
    logger.errorWithContext({ error: e, message: 'error POST /api/v1/auth/verify-token...'});
    return utils.returnErrorFunction(res, 'error POST /api/v1/auth/verify-token...', e);
  }
}