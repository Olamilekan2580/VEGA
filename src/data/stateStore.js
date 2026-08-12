const fs = require('fs');
const path = require('path');

let poolPromise = null;
let schemaReadyPromise = null;

const fileStorePath = path.join(__dirname, 'vegaverify-product-store.json');
const schemaPath = path.join(__dirname, '../db/vegaverify_supabase_schema.sql');

function hasDatabaseUrl() {
  return Boolean(process.env.DATABASE_URL);
}

async function getPool() {
  if (!hasDatabaseUrl()) {
    return null;
  }

  if (!poolPromise) {
    poolPromise = (async () => {
      const { Pool } = require('pg');
      return new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
      });
    })();
  }

  return poolPromise;
}

async function ensureSchema() {
  if (!hasDatabaseUrl()) {
    return;
  }

  if (!schemaReadyPromise) {
    schemaReadyPromise = (async () => {
      const pool = await getPool();
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      await pool.query(schemaSql);
    })();
  }

  await schemaReadyPromise;
}

function ensureFileStore(initialStateFactory) {
  if (!fs.existsSync(fileStorePath)) {
    fs.writeFileSync(fileStorePath, JSON.stringify(initialStateFactory(), null, 2));
  }
}

async function readState(initialStateFactory) {
  if (!hasDatabaseUrl()) {
    ensureFileStore(initialStateFactory);
    return JSON.parse(fs.readFileSync(fileStorePath, 'utf8'));
  }

  await ensureSchema();
  const pool = await getPool();
  const state = initialStateFactory();

  const [organizationsResult, usersResult, sessionsResult] = await Promise.all([
    pool.query('select id, workspace, invitations, created_at, updated_at from vega_organizations order by created_at asc'),
    pool.query('select id, organization_id, name, email, role, password, created_at from vega_users order by created_at asc'),
    pool.query('select id, user_id, token, created_at from vega_sessions order by created_at asc'),
  ]);

  state.organizations = organizationsResult.rows.map((row) => ({
    id: row.id,
    workspace: row.workspace,
    invitations: row.invitations || [],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));

  state.users = usersResult.rows.map((row) => ({
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    email: row.email,
    role: row.role,
    password: row.password,
    createdAt: row.created_at,
  }));

  state.sessions = sessionsResult.rows.map((row) => ({
    id: row.id,
    userId: row.user_id,
    token: row.token,
    createdAt: row.created_at,
  }));

  return state;
}

async function writeState(state) {
  if (!hasDatabaseUrl()) {
    fs.writeFileSync(fileStorePath, JSON.stringify(state, null, 2));
    return;
  }

  await ensureSchema();
  const pool = await getPool();
  const client = await pool.connect();

  try {
    await client.query('begin');
    await client.query('delete from vega_sessions');
    await client.query('delete from vega_users');
    await client.query('delete from vega_organizations');

    for (const organization of state.organizations) {
      await client.query(
        `insert into vega_organizations (id, name, workspace, invitations, created_at, updated_at)
         values ($1, $2, $3::jsonb, $4::jsonb, $5, $6)`,
        [
          organization.id,
          organization.workspace.organizationProfile.name,
          JSON.stringify(organization.workspace),
          JSON.stringify(organization.invitations || []),
          organization.createdAt || new Date().toISOString(),
          organization.updatedAt || new Date().toISOString(),
        ],
      );
    }

    for (const user of state.users) {
      await client.query(
        `insert into vega_users (id, organization_id, name, email, role, password, created_at)
         values ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
        [
          user.id,
          user.organizationId,
          user.name,
          user.email,
          user.role,
          JSON.stringify(user.password),
          user.createdAt || new Date().toISOString(),
        ],
      );
    }

    for (const session of state.sessions) {
      await client.query(
        `insert into vega_sessions (id, user_id, token, created_at)
         values ($1, $2, $3, $4)`,
        [session.id, session.userId, session.token, session.createdAt || new Date().toISOString()],
      );
    }

    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
}

function storageModeLabel() {
  return hasDatabaseUrl() ? 'Neon/Postgres via DATABASE_URL' : 'Local file persistence with Postgres-ready adapter';
}

module.exports = {
  readState,
  storageModeLabel,
  writeState,
};
