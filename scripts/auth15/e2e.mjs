// HU-AUTH-15 real-stack verification: Gateway -> Auth -> PostgreSQL, all owned by scripts/auth15/fixture.sh.
//
//   AUTH15_PRIVATE_DIR=... node scripts/auth15/e2e.mjs [--evidence <file.json>]
//
// It authenticates as the administrator the fixture created through the real HU-AUTH-14 command, so every ADMIN token
// below comes from a real login. It prints one line per check (id, acceptance criterion, outcome) and never prints a
// password, a token, a hash or a response body. Passwords it invents live in memory for the run. The evidence file holds
// the same sanitized lines plus the revisions that ran.
//
// Faults are injected only into the owned database (a REVOKE/GRANT on auth15-pg) and only into the owned containers
// (restart); nothing here knows how to reach another project's database or stack.
import { execFileSync } from 'node:child_process';
import { createSign, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const PRIV = process.env.AUTH15_PRIVATE_DIR;
if (!PRIV) { console.error('set AUTH15_PRIVATE_DIR'); process.exit(2); }
const GW = process.env.AUTH15_GATEWAY_URL ?? 'http://127.0.0.1:18085';
const DB = 'synkro_auth_disposable_auth15';
const PG = 'auth15-pg';
const API = 'auth15-auth-api';
const GATEWAY = 'auth15-gateway';
const evidenceIdx = process.argv.indexOf('--evidence');
const evidenceFile = evidenceIdx > 0 ? process.argv[evidenceIdx + 1] : null;

const run = randomBytes(4).toString('hex');
const secrets = new Set(); // everything that must never appear in a log, a response or the audit table
const secret = (value) => { secrets.add(value); return value; };
const newPassword = () => secret(`Pw-${randomBytes(12).toString('hex')}`);
const results = [];

// ── plumbing ──────────────────────────────────────────────────────────────────────────────────────────────────

const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const sql = (query) => execFileSync('docker', ['exec', '-i', PG, 'psql', '-U', 'postgres', '-d', DB, '-tA', '-v', 'ON_ERROR_STOP=1'],
  { input: query, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
const count = (query) => Number(sql(query));
const quote = (text) => `'${text.replaceAll("'", "''")}'`;

async function call(method, path, { token, body, key, correlation, headers = {} } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (token) h.Authorization = `Bearer ${token}`;
  if (key) h['Idempotency-Key'] = key;
  if (correlation) h['X-Correlation-Id'] = correlation;
  const response = await fetch(GW + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status, headers: response.headers, text, json };
}

const b64 = (input) => Buffer.from(input).toString('base64url');
const claimsOf = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
function signedToken(privateKeyPem, claims, alg = 'RS256') {
  const header = b64(JSON.stringify({ alg, typ: 'JWT' }));
  const payload = b64(JSON.stringify(claims));
  if (alg === 'none') return `${header}.${payload}.`;
  const signature = createSign('RSA-SHA256').update(`${header}.${payload}`).sign(privateKeyPem).toString('base64url');
  return `${header}.${payload}.${signature}`;
}

function check(id, criterion, title, ok, detail = '') {
  results.push({ id, criterion, title, ok: Boolean(ok), detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${id}  ${criterion}  ${title}${detail ? `  [${detail}]` : ''}`);
}

const registerBody = (label, role, password) => ({ name: `AUTH15 ${label}`, email: `auth15-${run}-${label}@synkro.test`, password, role });
const rowsFor = (email) => ({
  users: count(`SELECT count(*) FROM auth_schema.system_user WHERE email = ${quote(email)}`),
  audits: count(`SELECT count(*) FROM auth_schema.user_creation_audit a JOIN auth_schema.system_user u ON u.user_id = a.created_user_id WHERE u.email = ${quote(email)}`),
});
const keyRows = (key) => count(`SELECT count(*) FROM auth_schema.idempotency_key WHERE key = ${quote(key)}`);
const totals = () => `${count('SELECT count(*) FROM auth_schema.system_user')}/${count('SELECT count(*) FROM auth_schema.user_creation_audit')}/${count('SELECT count(*) FROM auth_schema.idempotency_key')}`;

async function until(probe, what, seconds = 60) {
  for (let i = 0; i < seconds; i++) {
    try { if (await probe()) return; } catch { /* not yet */ }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`timed out waiting for ${what}`);
}

// ── fixture state ─────────────────────────────────────────────────────────────────────────────────────────────

const adminPassword = secret(readFileSync(join(PRIV, 'admin_password'), 'utf8').trim());
secret(readFileSync(join(PRIV, 'auth_app_password'), 'utf8').trim());
secret(readFileSync(join(PRIV, 'pg_admin_password'), 'utf8').trim());
const signingKeyPem = readFileSync(join(PRIV, 'jwt-private.pem'), 'utf8');
const adminEmail = 'auth15-admin@synkro.test';

// The login rate budget of the gateway is 5 quick attempts per minute and IP (login zone). A fresh gateway process
// starts a fresh budget, which is what makes this script repeatable; restarting only our own container.
docker('restart', GATEWAY);
await until(async () => (await call('GET', '/health')).status === 200, 'the gateway');

// ── AUTH15-01 create and authenticate ─────────────────────────────────────────────────────────────────────────

const adminLogin = await call('POST', '/api/v1/auth/login', { body: { email: adminEmail, password: adminPassword } });
check('E2E-01', 'AUTH15-01', 'real login of the initial ADMIN through the gateway', adminLogin.status === 200 && adminLogin.json?.accessToken);
if (!adminLogin.json?.accessToken) { console.error('cannot continue without the ADMIN login; run fixture.sh reset'); process.exit(1); }
const admin = adminLogin.json.accessToken;
secret(admin); secret(adminLogin.json.refreshToken);
const adminId = claimsOf(admin).sub;
check('E2E-02', 'AUTH15-01', 'the ADMIN token is a human ADMIN token (roles=[ADMIN], sub=user id)',
  JSON.stringify(claimsOf(admin).roles) === '["ADMIN"]' && /^[0-9a-f-]{36}$/.test(adminId));

const salesPw = newPassword();
const salesBody = registerBody('sales', 'SALESPERSON', salesPw);
const salesKey = `auth15-${run}-key-sales`;
const correlation = `auth15-${run}-corr-1`;
const created = await call('POST', '/api/v1/auth/register', { token: admin, body: salesBody, key: salesKey, correlation });
const location = created.headers.get('location');
const salesId = created.json?.userId;
check('E2E-03', 'AUTH15-01', 'ADMIN registers a SALESPERSON: 201, Location points at the user, correlation echoed',
  created.status === 201 && location === `/api/v1/auth/users/${salesId}` && created.headers.get('x-correlation-id') === correlation,
  `status=${created.status}`);
check('E2E-04', 'AUTH15-01', 'the 201 body has the UserResponse fields and no password or hash',
  created.json && ['userId', 'name', 'email', 'role', 'registrationDate', 'active'].every((f) => f in created.json)
  && !('password' in created.json) && !('passwordHash' in created.json) && !created.text.includes(salesPw) && !created.text.includes('$2'));

const read = await call('GET', location, { token: admin });
check('E2E-05', 'AUTH15-01', 'safe read by the known id returns the same user', read.status === 200 && read.json?.userId === salesId
  && read.json.email === salesBody.email && read.json.role === 'SALESPERSON' && read.json.active === true && !('passwordHash' in read.json));

const salesLogin = await call('POST', '/api/v1/auth/login', { body: { email: salesBody.email, password: salesPw } });
const sales = salesLogin.json?.accessToken;
if (sales) { secret(sales); secret(salesLogin.json.refreshToken); }
check('E2E-06', 'AUTH15-01', 'the new account authenticates against the real service with its own role and id',
  salesLogin.status === 200 && sales && claimsOf(sales).sub === salesId && JSON.stringify(claimsOf(sales).roles) === '["SALESPERSON"]');

const invPw = newPassword();
const invBody = registerBody('inventory', 'INVENTORY', invPw);
const inventoryCreated = await call('POST', '/api/v1/auth/register', { token: admin, body: invBody, key: `auth15-${run}-key-inventory` });
const adm2Pw = newPassword();
const adm2Body = registerBody('admin2', 'ADMIN', adm2Pw);
const admin2Created = await call('POST', '/api/v1/auth/register', { token: admin, body: adm2Body, key: `auth15-${run}-key-admin2` });
check('E2E-07', 'AUTH15-01', 'ADMIN also creates INVENTORY and ADMIN accounts (each permitted human role)',
  inventoryCreated.status === 201 && admin2Created.status === 201);

const inventoryLogin = await call('POST', '/api/v1/auth/login', { body: { email: invBody.email, password: invPw } });
const inventory = inventoryLogin.json?.accessToken;
if (inventory) { secret(inventory); secret(inventoryLogin.json.refreshToken); }

const stored = sql(`SELECT password_hash FROM auth_schema.system_user WHERE email = ${quote(salesBody.email)}`);
check('E2E-08', 'AUTH15-04', 'the stored credential is a bcrypt hash that is not the password', /^\$2[aby]\$\d\d\$/.test(stored) && stored !== salesPw);
const audit = sql(`SELECT operation || '|' || actor_kind || '|' || actor_user_id || '|' || created_user_id || '|' || outcome || '|' || correlation_id
  FROM auth_schema.user_creation_audit WHERE created_user_id = ${quote(salesId)}`);
check('E2E-09', 'AUTH15-04', 'exactly one audit row attributes the creation to the ADMIN token subject and the request correlation id',
  audit === `USER_REGISTERED|ADMIN|${adminId}|${salesId}|SUCCESS|${correlation}`);
check('E2E-10', 'AUTH15-04', 'the audit row and the key row are single and point at the created user',
  rowsFor(salesBody.email).audits === 1 && keyRows(salesKey) === 1
  && count(`SELECT count(*) FROM auth_schema.idempotency_key WHERE key = ${quote(salesKey)} AND resource_id = ${quote(salesId)}`) === 1);

// ── AUTH15-02 unauthorized registration ───────────────────────────────────────────────────────────────────────

const serviceIssued = await call('POST', '/api/v1/auth/service-tokens', { token: admin, body: { service: 'synkro-workflow' }, key: `auth15-${run}-key-svc` });
const service = serviceIssued.json?.token;
if (service) secret(service);
check('E2E-11', 'AUTH15-02', 'a genuine SERVICE token is issued by the ADMIN for the negative cases', serviceIssued.status === 201 && Boolean(service));

const target = registerBody('blocked', 'INVENTORY', newPassword());
const before = totals();
const unauth = {
  'no credentials': {},
  'malformed token': { token: 'not-a-jwt' },
  'tampered signature': { token: `${admin.slice(0, -4)}AAAA` },
  'expired token': { token: signedToken(signingKeyPem, { sub: adminId, roles: ['ADMIN'], iat: 1, exp: 2, jti: randomUUID() }) },
  'token signed by another key': { token: signedToken(generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }), { sub: adminId, roles: ['ADMIN'], exp: Math.floor(Date.now() / 1000) + 600 }) },
  'unsecured (alg none) token': { token: signedToken('', { sub: adminId, roles: ['ADMIN'], exp: Math.floor(Date.now() / 1000) + 600 }, 'none') },
  'refresh token as bearer': { token: adminLogin.json.refreshToken },
};
for (const [label, options] of Object.entries(unauth)) {
  const response = await call('POST', '/api/v1/auth/register', { ...options, body: target, key: `auth15-${run}-key-blocked` });
  check(`E2E-12:${label}`, 'AUTH15-02', `${label} -> 401`, response.status === 401 && !response.text.includes(target.email), `status=${response.status}`);
}
const forbiddenTokens = { SALESPERSON: sales, INVENTORY: inventory, SERVICE: service };
for (const [role, token] of Object.entries(forbiddenTokens)) {
  const response = await call('POST', '/api/v1/auth/register', { token, body: target, key: `auth15-${run}-key-blocked` });
  check(`E2E-13:${role}`, 'AUTH15-02', `${role} -> 403 on a first attempt`, response.status === 403 && !response.text.includes(target.email), `status=${response.status}`);
}
for (const [role, token] of Object.entries(forbiddenTokens)) {
  const response = await call('POST', '/api/v1/auth/register', { token, body: salesBody, key: salesKey });
  check(`E2E-14:${role}`, 'AUTH15-02', `${role} replaying the ADMIN's exact request and key -> 403, nothing disclosed`,
    response.status === 403 && !response.text.includes(salesId) && !response.text.includes(salesBody.email), `status=${response.status}`);
}
const ghost = signedToken(signingKeyPem, { sub: randomUUID(), roles: ['ADMIN'], exp: Math.floor(Date.now() / 1000) + 600 });
const ghostResponse = await call('POST', '/api/v1/auth/register', { token: ghost, body: target, key: `auth15-${run}-key-blocked` });
check('E2E-15', 'AUTH15-02', 'a validly signed ADMIN token for a user that does not exist -> 403', ghostResponse.status === 403, `status=${ghostResponse.status}`);
check('E2E-16', 'AUTH15-02', 'no user, key or audit row changed during all refused attempts',
  totals() === before && rowsFor(target.email).users === 0 && keyRows(`auth15-${run}-key-blocked`) === 0);
const noSecretRead = await call('GET', `/api/v1/auth/users/${salesId}`, { token: sales });
check('E2E-17', 'AUTH15-02', 'a SALESPERSON cannot read the user either (lookup is ADMIN-only) -> 403', noSecretRead.status === 403);

// ── AUTH15-03 idempotency and invalid data ────────────────────────────────────────────────────────────────────

const replay = await call('POST', '/api/v1/auth/register', { token: admin, body: salesBody, key: salesKey, correlation: `auth15-${run}-corr-2` });
check('E2E-18', 'AUTH15-03', 'identical authorized replay -> 200 with the original user, once', replay.status === 200 && replay.json?.userId === salesId
  && rowsFor(salesBody.email).users === 1 && rowsFor(salesBody.email).audits === 1 && keyRows(salesKey) === 1, `status=${replay.status}`);
check('E2E-19', 'AUTH15-03', 'the replay did not overwrite the original audit correlation id',
  sql(`SELECT correlation_id FROM auth_schema.user_creation_audit WHERE created_user_id = ${quote(salesId)}`) === correlation);
const secondAdminToken = (await call('POST', '/api/v1/auth/login', { body: { email: adm2Body.email, password: adm2Pw } })).json?.accessToken;
if (secondAdminToken) secret(secondAdminToken);
const otherAdminReplay = secondAdminToken && await call('POST', '/api/v1/auth/register', { token: secondAdminToken, body: salesBody, key: salesKey });
check('E2E-20', 'AUTH15-03', 'a different ADMIN replaying the same request and key gets the original user, no second audit row',
  otherAdminReplay?.status === 200 && otherAdminReplay.json?.userId === salesId && rowsFor(salesBody.email).audits === 1,
  `status=${otherAdminReplay?.status}`);

const changed = await call('POST', '/api/v1/auth/register', { token: admin, body: { ...salesBody, name: 'Somebody Else' }, key: salesKey });
check('E2E-21', 'AUTH15-03', 'same key with a changed intention -> 422 naming Idempotency-Key, original not shown',
  changed.status === 422 && changed.json?.error === 'BUSINESS_RULE_VIOLATION' && !changed.text.includes(salesId), `status=${changed.status}`);
const duplicate = await call('POST', '/api/v1/auth/register', { token: admin, body: salesBody, key: `auth15-${run}-key-dup` });
check('E2E-22', 'AUTH15-03', 'same email with a new key -> 422 BUSINESS_RULE_VIOLATION on email, no key or row left',
  duplicate.status === 422 && JSON.stringify(duplicate.json).includes('email') && keyRows(`auth15-${run}-key-dup`) === 0 && rowsFor(salesBody.email).users === 1,
  `status=${duplicate.status}`);
const duplicateCase = await call('POST', '/api/v1/auth/register', { token: admin, body: { ...salesBody, email: ` ${salesBody.email.toUpperCase()} ` }, key: `auth15-${run}-key-dup2` });
check('E2E-23', 'AUTH15-03', 'the same email in another case or with spaces is still a duplicate -> 422', duplicateCase.status === 422, `status=${duplicateCase.status}`);

const invalidCases = {
  'role SERVICE': { ...registerBody('bad1', 'SERVICE', 'long-enough-1') },
  'unknown role': { ...registerBody('bad2', 'OWNER', 'long-enough-1') },
  'short password': { ...registerBody('bad3', 'INVENTORY', 'short') },
  'password over 72 bytes': { ...registerBody('bad4', 'INVENTORY', 'x'.repeat(73)) },
  'malformed email': { ...registerBody('bad5', 'INVENTORY', 'long-enough-1'), email: 'not-an-email' },
  'blank name': { ...registerBody('bad6', 'INVENTORY', 'long-enough-1'), name: '   ' },
  'missing fields': {},
};
for (const [label, body] of Object.entries(invalidCases)) {
  const k = `auth15-${run}-key-${label.replaceAll(' ', '-')}`;
  const bad = await call('POST', '/api/v1/auth/register', { token: admin, body, key: k });
  check(`E2E-24:${label}`, 'AUTH15-03', `${label} -> 400 VALIDATION_ERROR, nothing written`,
    bad.status === 400 && keyRows(k) === 0 && (!body.email || rowsFor(body.email).users === 0), `status=${bad.status}`);
}
for (const [label, key] of [['missing key', undefined], ['short key', 'short'], ['129-char key', 'k'.repeat(129)]]) {
  const bad = await call('POST', '/api/v1/auth/register', { token: admin, body: registerBody('badkey', 'INVENTORY', 'long-enough-1'), key });
  check(`E2E-25:${label}`, 'AUTH15-03', `${label} -> 400`, bad.status === 400 && rowsFor(`auth15-${run}-badkey@synkro.test`).users === 0, `status=${bad.status}`);
}

const racePw = newPassword();
const raceBody = registerBody('race', 'INVENTORY', racePw);
const raceKey = `auth15-${run}-key-race`;
const race = await Promise.all(Array.from({ length: 8 }, () => call('POST', '/api/v1/auth/register', { token: admin, body: raceBody, key: raceKey })));
const statuses = race.map((r) => r.status).sort();
check('E2E-26', 'AUTH15-03', 'eight simultaneous identical requests -> one 201, the rest 200, one user, one audit row',
  statuses.filter((s) => s === 201).length === 1 && statuses.filter((s) => s === 200).length === 7
  && new Set(race.map((r) => r.json?.userId)).size === 1 && rowsFor(raceBody.email).users === 1 && rowsFor(raceBody.email).audits === 1, statuses.join(','));

// ── AUTH15-04 atomicity, rollback, restart and redaction ──────────────────────────────────────────────────────

const failPw = newPassword();
const failBody = registerBody('rollback', 'INVENTORY', failPw);
const failKey = `auth15-${run}-key-rollback`;
// Owned fault seam: the audit insert is made to fail by revoking the privilege inside the disposable database.
sql('REVOKE INSERT ON TABLE auth_schema.user_creation_audit FROM auth_writer');
let failed;
try {
  failed = await call('POST', '/api/v1/auth/register', { token: admin, body: failBody, key: failKey });
} finally {
  sql('GRANT INSERT ON TABLE auth_schema.user_creation_audit TO auth_writer');
}
check('E2E-27', 'AUTH15-04', 'an audit insert that fails -> 500 in the common envelope without SQL or secrets',
  failed.status === 500 && failed.json?.error && !/(sql|insert|auth_schema|permission|denied)/i.test(failed.text) && !failed.text.includes(failPw), `status=${failed.status}`);
check('E2E-28', 'AUTH15-04', 'the failed registration left no user, no key and no audit row (rolled back together)',
  rowsFor(failBody.email).users === 0 && rowsFor(failBody.email).audits === 0 && keyRows(failKey) === 0);
const retried = await call('POST', '/api/v1/auth/register', { token: admin, body: failBody, key: failKey });
check('E2E-29', 'AUTH15-04', 'after the fault is gone the same key retried -> 201 (the key was released by the rollback)',
  retried.status === 201 && rowsFor(failBody.email).users === 1 && rowsFor(failBody.email).audits === 1, `status=${retried.status}`);

const snapshot = totals();
docker('restart', PG);
await until(() => sql('SELECT 1') === '1', 'the owned PostgreSQL after restart');
await until(async () => (await call('GET', '/api/v1/auth/users/' + salesId, { token: admin })).status === 200, 'Auth to reconnect to the restarted database');
check('E2E-30', 'AUTH15-04', 'after the database restarted, rows, keys and audit rows are exactly as before', totals() === snapshot, snapshot);
const afterRestart = await call('POST', '/api/v1/auth/login', { body: { email: salesBody.email, password: salesPw } });
check('E2E-31', 'AUTH15-04', 'after the database restarted, the created account still authenticates', afterRestart.status === 200);
docker('restart', API);
await until(async () => (await call('GET', '/api/v1/auth/users/' + salesId, { token: admin })).status === 200, 'Auth after its own restart');
const afterApiRestart = await call('POST', '/api/v1/auth/register', { token: admin, body: salesBody, key: salesKey });
check('E2E-32', 'AUTH15-04', 'after the Auth process restarted, the same request and key still replays the original user',
  afterApiRestart.status === 200 && afterApiRestart.json?.userId === salesId && totals() === snapshot, `status=${afterApiRestart.status}`);

const dump = [docker('logs', API), docker('logs', GATEWAY), sql('SELECT row_to_json(a)::text FROM auth_schema.user_creation_audit a'),
  sql('SELECT key || resource_type || resource_id FROM auth_schema.idempotency_key')].join('\n');
const leaked = [...secrets].filter((s) => s && dump.includes(s));
check('E2E-33', 'AUTH15-04', 'no password, token or refresh token appears in Auth logs, Gateway logs, audit rows or key rows', leaked.length === 0, `leaks=${leaked.length}`);
check('E2E-34', 'AUTH15-04', 'no bcrypt hash appears in the logs or the audit table', !/\$2[aby]\$\d\d\$/.test(dump));

// ── report ────────────────────────────────────────────────────────────────────────────────────────────────────

const failedChecks = results.filter((r) => !r.ok);
console.log(`\n${results.length - failedChecks.length}/${results.length} checks passed`);
if (evidenceFile) {
  const revisions = {};
  try { revisions.authImage = readFileSync(join(PRIV, 'images.env'), 'utf8').trim().split('\n'); } catch { /* optional */ }
  writeFileSync(evidenceFile, JSON.stringify({ run, gateway: GW, revisions, results }, null, 2));
}
process.exit(failedChecks.length === 0 ? 0 : 1);
