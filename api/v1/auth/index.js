const express = require('express');
const router = express.Router();
const controller = require('./controller');

router.post('/login', controller.getLogin);

router.get('/logout', controller.verifyTokenSelft, controller.getLogout);

router.post('/pre-register', controller.getPreRegister);

router.post('/post-register', controller.getPostRegister);

router.get('/verify-token', controller.verifyToken);

router.post('/ubah-pin', controller.verifyTokenSelft, controller.ubahPin);

router.post('/lupa-pin', controller.lupaPin);

module.exports = router;