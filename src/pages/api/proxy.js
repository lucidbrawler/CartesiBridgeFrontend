// src/pages/api/proxy.js
// Update: Hardcode or env-var the prod nodeBase for safety.
// Use process.env.NODE_BASE if set (add to Netlify env vars: NODE_BASE=https://warthognode.duckdns.org),
// fallback to public node for dev.

import https from 'https';  // For custom agent

export const prerender = false;

const agent = new https.Agent({
  rejectUnauthorized: false,  // Bypass strict cert validation (use only if cert errors occur; insecure for untrusted nodes)
});

export const GET = async ({ request }) => {
  try {
    const url = new URL(request.url);
    const nodePath = url.searchParams.get('nodePath');
    const nodeBase = url.searchParams.get('nodeBase') || process.env.NODE_BASE || 'https://node.wartscan.io';
    console.log(`[GET] Proxying to: ${nodeBase}/${nodePath}`); // Debug log
    if (!nodePath) {
      return new Response(JSON.stringify({ error: 'Missing nodePath query parameter' }), { status: 400 });
    }
    const targetUrl = `${nodeBase}/${nodePath}`;
    const response = await fetch(targetUrl, {
      headers: { 'Content-Type': 'application/json' },
      agent: targetUrl.startsWith('https') ? agent : undefined,  // Apply agent only for HTTPS
    });
    const data = await response.text();
    console.log(`[GET] Response status: ${response.status}, data: ${data}`); // Debug log
    return new Response(data, {
      status: response.status,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  } catch (err) {
    console.error('[GET] Proxy error:', err.message, err.stack);  // Enhanced logging
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
};

export const POST = async ({ request }) => {
  try {
    const url = new URL(request.url);
    const nodePath = url.searchParams.get('nodePath');
    const nodeBase = url.searchParams.get('nodeBase') || process.env.NODE_BASE || 'https://node.wartscan.io'; 
    console.log(`[POST] Proxying to: ${nodeBase}/${nodePath}`); // Debug log
    if (!nodePath) {
      return new Response(JSON.stringify({ error: 'Missing nodePath query parameter' }), { status: 400 });
    }
    const body = await request.json();
    const targetUrl = `${nodeBase}/${nodePath}`;
    const response = await fetch(targetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      agent: targetUrl.startsWith('https') ? agent : undefined,
    });
    const data = await response.text();
    console.log(`[POST] Response status: ${response.status}, data: ${data}`); // Debug log
    return new Response(data, {
      status: response.status,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  } catch (err) {
    console.error('[POST] Proxy error:', err.message, err.stack);
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
};

// Handle OPTIONS for CORS preflight
export const OPTIONS = async () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
};