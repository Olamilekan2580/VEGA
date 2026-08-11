const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const supabaseAdmin = require('../config/supabase');
router.use(requireAuth);
router.get('/', async (req, res) => {
  const { data, error } = await supabaseAdmin.from('projects').select('*, clients(name)').eq('freelancer_id', req.user.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
router.post('/', async (req, res) => {
  const { client_id, name, description, value, deadline } = req.body;
  if (!client_id || !name) return res.status(400).json({ error: 'Client ID and Project Name required' });
  const { data, error } = await supabaseAdmin.from('projects').insert([{ freelancer_id: req.user.id, client_id, name, description, value, deadline }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});
module.exports = router;
