'use stricts';

const express = require('express');
const router = express.Router();
const controller = require('./controller');

router.post('/verify-dekrip-token', controller.verifyAndDekripToken);

router.post('/verify-dekrip-token-refresh', controller.verifyAndDekripTokenRefresh);

module.exports = router;