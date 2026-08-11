const express = require('express');
const {
  applyAction,
  createRequestFromTemplate,
  getDashboard,
  resetStore,
} = require('../data/verifyStore');

const router = express.Router();

router.get('/bootstrap', (req, res, next) => {
  try {
    res.json(getDashboard(req.query.requestId));
  } catch (error) {
    next(error);
  }
});

router.post('/requests', (req, res, next) => {
  try {
    res.status(201).json(createRequestFromTemplate(req.body.templateKey));
  } catch (error) {
    next(error);
  }
});

router.post('/requests/:requestId/actions', (req, res, next) => {
  try {
    res.json(applyAction(req.params.requestId, req.body));
  } catch (error) {
    next(error);
  }
});

router.post('/reset-demo', (req, res, next) => {
  try {
    res.json(resetStore());
  } catch (error) {
    next(error);
  }
});

module.exports = router;
