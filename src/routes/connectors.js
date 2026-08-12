const express = require('express');
const { ingestServiceNowEvent } = require('../data/productStore');

const router = express.Router();

router.post('/servicenow/events', async (req, res, next) => {
  try {
    const secret = req.headers['x-vega-secret'] || req.headers['x-connector-secret'] || '';
    res.status(201).json(await ingestServiceNowEvent(secret, req.body || {}));
  } catch (error) {
    next(error);
  }
});

module.exports = router;
