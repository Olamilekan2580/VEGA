const { bootstrapAuth } = require('../data/productStore');

function getBearerToken(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return '';
  }

  return authHeader.slice('Bearer '.length).trim();
}

async function requireProductAuth(req, res, next) {
  const token = getBearerToken(req);

  try {
    const authState = await bootstrapAuth(token);
    if (!authState.session) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    req.productSession = authState.session;
    req.productToken = token;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

module.exports = { getBearerToken, requireProductAuth };
