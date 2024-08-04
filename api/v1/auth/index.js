const express = require('express');
const router = express.Router();
const controller = require('./controller');

router.post('/login', controller.getLogin);

router.get('/logout', controller.verifyTokenSelft, controller.getLogout);

router.post('/pre-register', controller.getPreRegister);

router.post('/post-register', controller.getPostRegister);

router.get('/verify-token', controller.verifyToken);

router.post('/lupa-pin', controller.verifyTokenSelft, controller.lupaPin);

module.exports = router;