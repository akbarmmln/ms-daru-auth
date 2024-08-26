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

module.exports = router;