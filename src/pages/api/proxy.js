// src/pages/api/proxy.js
export async function GET({ request }) {
  const url = new URL(request.url);
  const nodePath = url.searchParams.get('nodePath');
  const nodeBase = url.searchParams.get('nodeBase');

  if (!nodePath || !nodeBase) {
    return new Response(JSON.stringify({ error: 'Missing nodePath or nodeBase' }), { status: 400 });
  }

  try {
    const response = await fetch(`${nodeBase}/${nodePath}`);
    if (!response.ok) {
      throw new Error(`Failed to fetch: ${response.statusText}`);
    }
    const data = await response.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Proxy error:', error);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
}

export async function POST({ request }) {
  const url = new URL(request.url);
  const nodePath = url.searchParams.get('nodePath');
  const nodeBase = url.searchParams.get('nodeBase');

  if (!nodePath || !nodeBase) {
    return new Response(JSON.stringify({ error: 'Missing nodePath or nodeBase' }), { status: 400 });
  }

  try {
    const body = await request.json();
    const response = await fetch(`${nodeBase}/${nodePath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch: ${response.statusText}`);
    }
    const data = await response.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Proxy error:', error);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
}