const { createHmac, timingSafeEqual, scrypt } = require('node:crypto');
const derive = require('node:util').promisify(scrypt);
const namePattern = /^[a-z0-9_.-]{1,64}$/;
const hashPattern = /^[0-9a-f]{32}:[0-9a-f]{64}$/;
const dummy = '0'.repeat(32) + ':' + '0'.repeat(64);

function sign(value, hash, secret) {
  return createHmac('sha256', secret).update('kamuti-session-v1|' + value + '|' + hash).digest('hex');
}

function sessionCookie(value, seconds) {
  return '__Host-kamuti=' + value + '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=' + seconds;
}

async function authorize(request, response) {
  const secret = process.env.KAMUTI_ACCESS_KEY;
  let users;
  try { users = JSON.parse(process.env.KAMUTI_USERS_JSON || '{}'); } catch {}
  if (!secret || secret.length < 32 || !users || typeof users !== 'object' || !Object.keys(users).length) {
    response.status(503).json({error:'User accounts have not been configured.'});
    return false;
  }
  function lookup(name) {
    return namePattern.test(name) && Object.hasOwn(users, name) && hashPattern.test(users[name]) ? users[name] : '';
  }
  if (request.method === 'POST') {
    if (!(request.headers['content-type'] || '').startsWith('application/json')) {
      response.status(415).end(); return false;
    }
    const {username, password, logout} = request.body || {};
    if (logout === true) {
      response.setHeader('Set-Cookie', sessionCookie('', 0));
      response.status(204).end(); return false;
    }
    const name = typeof username === 'string' ? username.trim().toLowerCase() : '';
    const record = lookup(name);
    const [salt, expected] = (record || dummy).split(':');
    const validInput = typeof password === 'string' && password.length > 0 && password.length <= 256;
    const actual = await derive(validInput ? password : '', Buffer.from(salt,'hex'), 32);
    if (timingSafeEqual(actual, Buffer.from(expected,'hex')) && record && validInput) {
      const value = name + '~' + (Math.floor(Date.now()/1000) + 43200);
      response.setHeader('Set-Cookie', sessionCookie(value + '~' + sign(value, record, secret), 43200));
      response.status(204).end(); return false;
    }
  } else {
    const cookie = (request.headers.cookie || '').split(/;\s*/).find(v => v.startsWith('__Host-kamuti='));
    const [name, expires, signature] = (cookie || '').slice('__Host-kamuti='.length).split('~');
    const record = lookup(name || '');
    if (record && Number(expires) > Date.now()/1000 && /^[a-f0-9]{64}$/.test(signature || '')) {
      const expected = sign(name + '~' + expires, record, secret);
      if (timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) return true;
    }
  }
  response.status(401).json({error:request.method === 'POST' ? 'Incorrect username or password.' : 'Please sign in.'});
  return false;
}
module.exports = async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (!['GET','POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return response.status(405).json({error: 'Method not allowed'});
  }

  const { KAMUTI_ACCESS_KEY, KAMUTI_BRIDGE_KEY, KAMUTI_SCRIPT_URL } = process.env;
  if (!KAMUTI_ACCESS_KEY || !KAMUTI_BRIDGE_KEY || !KAMUTI_SCRIPT_URL) {
    return response.status(503).json({error: 'The live connection is not configured in Vercel.'});
  }
  if (!await authorize(request, response)) return;

  try {
    if (!/^https:\/\/script\.google\.com\/macros\/s\/[\w-]+\/exec$/.test(KAMUTI_SCRIPT_URL)) {
      return response.status(503).json({error: 'The Apps Script /exec URL is invalid.'});
    }
    const signal = AbortSignal.timeout(12000);
    let upstream = await fetch(KAMUTI_SCRIPT_URL, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({key: KAMUTI_BRIDGE_KEY}), redirect: 'manual', signal,
    });
    // Content Service usually redirects the generated response to googleusercontent.
    if ([301, 302, 303].includes(upstream.status)) {
      const location = new URL(upstream.headers.get('location') || '');
      if (location.origin !== 'https://script.googleusercontent.com') {
        return response.status(502).json({error: 'Apps Script redirected to a sign-in page. Check deployment access.'});
      }
      upstream = await fetch(location, {redirect: 'error', signal});
    }
    const data = upstream.ok ? await upstream.json() : null;
    if (!data?.ok) return response.status(502).json({error: 'Apps Script rejected the request. Check its bridge key, Sheet ID, and permissions.'});
    return response.status(200).json({events: data.events, accounts: data.accounts, totalLeads: data.totalLeads});
  } catch (error) {
    return response.status(502).json({error: 'Could not read the Apps Script response.'});
  }
};
