const express = require('express');
const router = express.Router();
const controller = require('./controller');

router.post('/login', controller.getLogin);

router.get('/logout', controller.verifyTokenSelft, controller.getLogout);

router.post('/pre-register', controller.getPreRegister);

router.post('/post-register', controller.getPostRegister);

router.post('/verify-token', controller.verifyToken);

router.post('/refresh-token', controller.refreshToken);

router.post('/ubah-pin', controller.verifyTokenSelft, controller.ubahPin);

router.post('/lupa-pin', controller.lupaPin);

router.post('/verify-pin', controller.verifyTokenSelft, controller.verifyPin);
router.post('/verify-code-trx', controller.verifyTokenSelft, controller.verifyCodeTrx);

router.get('/position/account', controller.verifyTokenSelft, controller.positionAccount);

module.exports = router;