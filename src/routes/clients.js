const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const supabaseAdmin = require('../config/supabase');
router.use(requireAuth);
router.get('/', async (req, res) => {
  const { data, error } = await supabaseAdmin.from('clients').select('*').eq('freelancer_id', req.user.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
router.post('/', async (req, res) => {
  const { name, email, phone, company } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
  const { data, error } = await supabaseAdmin.from('clients').insert([{ freelancer_id: req.user.id, name, email, phone, company }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});
module.exports = router;
