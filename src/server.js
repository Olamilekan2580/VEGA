require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const supabaseAdmin = require('./config/supabase');
const { sanitizeRequest } = require('./middleware/sanitize');
const { storageModeLabel } = require('./data/stateStore');

const clientsRouter = require('./routes/clients');
const projectsRouter = require('./routes/projects');
const invoicesRouter = require('./routes/invoices');
const proposalsRouter = require('./routes/proposals');
const messagesRouter = require('./routes/messages');
const portalRouter = require('./routes/portal');
const connectorsRouter = require('./routes/connectors');
const productAuthRouter = require('./routes/productAuth');
const verifyRouter = require('./routes/verify');

const app = express();
app.use(helmet());
app.use(sanitizeRequest);
app.use(hpp());
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5173', credentials: true }));

app.use('/api/webhooks/paystack', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10kb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api', limiter);

app.use('/api/auth', productAuthRouter);
app.use('/api/verify', verifyRouter);
app.use('/api/connectors', connectorsRouter);

if (supabaseAdmin) {
  app.use('/api/clients', clientsRouter);
  app.use('/api/projects', projectsRouter);
  app.use('/api/invoices', invoicesRouter);
  app.use('/api/proposals', proposalsRouter);
  app.use('/api/messages', messagesRouter);
  app.use('/api/portal', portalRouter);
}

app.get('/api/health', (req, res) =>
  res.status(200).json({
    status: 'ok',
    service: 'VegaVerify API',
    demoMode: !process.env.DATABASE_URL,
    storage: storageModeLabel(),
  }),
);

app.use((err, req, res, next) => {
  console.error('[System Error]:', err.message);
  res.status(err.status || 500).json({ error: 'Internal Server Error' });
});

if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => console.log(`[SECURE] API Gateway operational on port ${PORT}`));
}

module.exports = app;
