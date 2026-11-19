const { timingSafeEqual } = require('node:crypto');

function matchesKey(actual, expected) {
  const provided = Buffer.from(actual || '');
  const required = Buffer.from(expected || '');
  return required.length >= 32 && provided.length === required.length && timingSafeEqual(provided, required);
}

module.exports = async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({error: 'Method not allowed'});
  }

  const { KAMUTI_ACCESS_KEY, KAMUTI_BRIDGE_KEY, KAMUTI_SCRIPT_URL } = process.env;
  if (!KAMUTI_ACCESS_KEY || !KAMUTI_BRIDGE_KEY || !KAMUTI_SCRIPT_URL) {
    return response.status(503).json({error: 'The live connection is not configured in Vercel.'});
  }
  const authorization = request.headers.authorization || '';
  if (!matchesKey(authorization.startsWith('Bearer ') ? authorization.slice(7) : '', KAMUTI_ACCESS_KEY)) {
    return response.status(401).json({error: 'The access key is incorrect.'});
  }

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
