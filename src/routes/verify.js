const express = require('express');
const {
  getWorkspaceForToken,
  inviteMember,
  mutateWorkspace,
  resetWorkspace,
  rotateServiceNowSecret,
  updateOrganization,
  updateServiceNowConnector,
} = require('../data/productStore');
const { requireProductAuth } = require('../middleware/productAuth');

const router = express.Router();

router.use(requireProductAuth);

router.get('/bootstrap', async (req, res, next) => {
  try {
    res.json(await getWorkspaceForToken(req.productToken, req.query.requestId || ''));
  } catch (error) {
    next(error);
  }
});

router.post('/requests', async (req, res, next) => {
  try {
    res.status(201).json(
      await mutateWorkspace(req.productToken, {
        type: 'create_request',
        templateKey: req.body?.templateKey,
      }),
    );
  } catch (error) {
    next(error);
  }
});

router.post('/requests/:requestId/actions', async (req, res, next) => {
  try {
    res.json(
      await mutateWorkspace(req.productToken, {
        type: 'request_action',
        requestId: req.params.requestId,
        action: req.body || {},
      }),
    );
  } catch (error) {
    next(error);
  }
});

router.put('/organization', async (req, res, next) => {
  try {
    res.json(await updateOrganization(req.productToken, req.body || {}));
  } catch (error) {
    next(error);
  }
});

router.post('/team/invitations', async (req, res, next) => {
  try {
    res.status(201).json(await inviteMember(req.productToken, req.body || {}));
  } catch (error) {
    next(error);
  }
});

router.put('/connectors/servicenow', async (req, res, next) => {
  try {
    res.json(await updateServiceNowConnector(req.productToken, req.body || {}));
  } catch (error) {
    next(error);
  }
});

router.post('/connectors/servicenow/rotate-secret', async (req, res, next) => {
  try {
    res.json(await rotateServiceNowSecret(req.productToken));
  } catch (error) {
    next(error);
  }
});

router.post('/reset-demo', async (req, res, next) => {
  try {
    res.json(await resetWorkspace(req.productToken));
  } catch (error) {
    next(error);
  }
});

module.exports = router;
