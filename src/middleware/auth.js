const supabaseAdmin = require('../config/supabase');

const requireAuth = async (req, res, next) => {
  try {
    if (!supabaseAdmin) {
      return res.status(503).json({ error: 'Supabase auth is not configured for this environment' });
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized: Missing token' });
    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    req.user = user;
    next();
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error during authentication' });
  }
};
module.exports = { requireAuth };
