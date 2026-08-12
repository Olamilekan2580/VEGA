create table if not exists vega_organizations (
  id uuid primary key,
  name text not null,
  workspace jsonb not null,
  invitations jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists vega_users (
  id uuid primary key,
  organization_id uuid not null references vega_organizations(id) on delete cascade,
  name text not null,
  email text not null unique,
  role text not null,
  password jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists vega_sessions (
  id uuid primary key,
  user_id uuid not null references vega_users(id) on delete cascade,
  token text not null unique,
  created_at timestamptz not null default now()
);

create index if not exists vega_users_org_idx on vega_users (organization_id);
create index if not exists vega_sessions_user_idx on vega_sessions (user_id);
