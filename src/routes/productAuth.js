const express = require('express');
const { acceptInvite, bootstrapAuth, signIn, signOut, signUp } = require('../data/productStore');
const { getBearerToken } = require('../middleware/productAuth');

const router = express.Router();

router.get('/bootstrap', async (req, res, next) => {
  try {
    res.json(await bootstrapAuth(getBearerToken(req)));
  } catch (error) {
    next(error);
  }
});

router.post('/signup', async (req, res, next) => {
  try {
    res.status(201).json(await signUp(req.body || {}));
  } catch (error) {
    next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    res.json(await signIn(req.body || {}));
  } catch (error) {
    next(error);
  }
});

router.post('/accept-invite', async (req, res, next) => {
  try {
    res.status(201).json(await acceptInvite(req.body || {}));
  } catch (error) {
    next(error);
  }
});

router.post('/logout', async (req, res, next) => {
  try {
    await signOut(getBearerToken(req));
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

module.exports = router;
