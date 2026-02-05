// Cloudflare Worker — Ahana Hillside API
// Handles: iCal calendar proxy, site configuration, admin authentication
// Requires KV Namespace binding: CONFIG
// Deploy: paste into Cloudflare Workers dashboard

const ICAL_FEEDS = {
  samavas: 'https://www.hipcamp.com/en-AU/bookings/cc06b2c9-7536-49df-a407-4bac49630d71/agenda.ics?cal=92310&s=940738',
  chhaya: 'https://www.hipcamp.com/en-AU/bookings/cc06b2c9-7536-49df-a407-4bac49630d71/agenda.ics?cal=92309&s=1103648',
};

const ALLOWED_ORIGINS = [
  'https://ahanahillside.com',
  'https://www.ahanahillside.com',
  'https://ahanahillside.github.io',
  'http://localhost',
  'http://127.0.0.1',
];

const DEFAULT_CONFIG = {
  samavas: {
    name: 'SAMAVAS',
    type: 'RV / Tent Site · Sleeps 15 · Vehicles under 30 m',
    description: 'Our largest site, accommodating up to 15 people. Set furthest from the main house for maximum privacy, SAMAVAS is ideal for groups and families looking for a secluded spot in the rainforest.',
    basePrice: 66,
    extraGuestFee: 15,
    maxGuests: 20,
  },
  chhaya: {
    name: 'CHHAYA',
    type: 'RV / Tent Site · Sleeps 6 · Vehicles under 24 m',
    description: 'A cosy, intimate site perfect for couples and solo campers. CHHAYA is just a few metres from the toilets, offering convenience without sacrificing the peaceful rainforest setting.',
    basePrice: 60,
    extraGuestFee: 10,
    maxGuests: 20,
  },
  currency: 'AUD',
  promoCodes: {},
  rules: [
    'No parties allowed without prior permission',
    'No loud or open music',
    'All dogs must be kept on a leash when on the main campground',
  ],
};

const DEFAULT_PASSWORD = 'ahana2026';

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.some(o => origin && origin.startsWith(o));
  return {
    'Access-Control-Allow-Origin': allowed ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonResponse(data, status, origin, cache) {
  const headers = { 'Content-Type': 'application/json', ...corsHeaders(origin) };
  if (cache) headers['Cache-Control'] = cache;
  return new Response(JSON.stringify(data), { status, headers });
}

function parseIcal(icsText) {
  const events = [];
  const blocks = icsText.split('BEGIN:VEVENT');

  for (let i = 1; i < blocks.length; i++) {
    const block = blocks[i].split('END:VEVENT')[0];
    const dtstart = block.match(/DTSTART[^:]*:(\d{8})/);
    const dtend = block.match(/DTEND[^:]*:(\d{8})/);
    const summary = block.match(/SUMMARY:(.*)/);

    if (dtstart) {
      const start = dtstart[1];
      const end = dtend ? dtend[1] : start;

      const dates = [];
      const current = new Date(
        parseInt(start.slice(0, 4)),
        parseInt(start.slice(4, 6)) - 1,
        parseInt(start.slice(6, 8))
      );
      const endDate = new Date(
        parseInt(end.slice(0, 4)),
        parseInt(end.slice(4, 6)) - 1,
        parseInt(end.slice(6, 8))
      );

      while (current < endDate) {
        dates.push(current.toISOString().split('T')[0]);
        current.setDate(current.getDate() + 1);
      }

      events.push({
        start: `${start.slice(0, 4)}-${start.slice(4, 6)}-${start.slice(6, 8)}`,
        end: `${end.slice(0, 4)}-${end.slice(4, 6)}-${end.slice(6, 8)}`,
        summary: summary ? summary[1].trim() : 'Booked',
        dates,
      });
    }
  }

  return events;
}

async function getConfig(env) {
  try {
    const stored = await env.CONFIG.get('site-config', 'json');
    if (stored) return stored;
  } catch (e) {
    // KV not bound or empty — use defaults
  }
  return DEFAULT_CONFIG;
}

async function getPassword(env) {
  try {
    const pwd = await env.CONFIG.get('admin-password');
    if (pwd) return pwd;
  } catch (e) {}
  return DEFAULT_PASSWORD;
}

async function verifyAuth(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '');
  const password = await getPassword(env);
  return token === password;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // --- GET /config — public, returns site configuration ---
    if (path === '/config' && request.method === 'GET') {
      const config = await getConfig(env);
      return jsonResponse(config, 200, origin, 'public, max-age=60');
    }

    // --- POST /config — admin only, updates site configuration ---
    if (path === '/config' && request.method === 'POST') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const newConfig = await request.json();
        await env.CONFIG.put('site-config', JSON.stringify(newConfig));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Invalid data', detail: err.message }, 400, origin);
      }
    }

    // --- POST /auth — login, returns token on success ---
    if (path === '/auth' && request.method === 'POST') {
      try {
        const { password } = await request.json();
        const stored = await getPassword(env);
        if (password === stored) {
          return jsonResponse({ success: true, token: stored }, 200, origin);
        }
        return jsonResponse({ error: 'Invalid password' }, 401, origin);
      } catch (err) {
        return jsonResponse({ error: 'Invalid request' }, 400, origin);
      }
    }

    // --- POST /password — admin only, changes admin password ---
    if (path === '/password' && request.method === 'POST') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const { newPassword } = await request.json();
        if (!newPassword || newPassword.length < 6) {
          return jsonResponse({ error: 'Password must be at least 6 characters' }, 400, origin);
        }
        await env.CONFIG.put('admin-password', newPassword);
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Invalid request' }, 400, origin);
      }
    }

    // --- POST /messages — public, stores a contact message ---
    if (path === '/messages' && request.method === 'POST') {
      try {
        const msg = await request.json();
        if (!msg.name || !msg.email || !msg.message) {
          return jsonResponse({ error: 'Name, email, and message are required' }, 400, origin);
        }

        // Get existing messages
        let messages = [];
        try {
          const stored = await env.CONFIG.get('messages', 'json');
          if (stored) messages = stored;
        } catch (e) {}

        // Add new message with unique ID
        messages.unshift({
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
          name: msg.name.slice(0, 200),
          email: msg.email.slice(0, 200),
          subject: (msg.subject || 'No subject').slice(0, 200),
          message: msg.message.slice(0, 5000),
          date: msg.date || new Date().toISOString(),
          read: false,
        });

        // Keep max 200 messages
        if (messages.length > 200) messages = messages.slice(0, 200);

        await env.CONFIG.put('messages', JSON.stringify(messages));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed to save message', detail: err.message }, 500, origin);
      }
    }

    // --- GET /messages — admin only, returns all messages ---
    if (path === '/messages' && request.method === 'GET') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const messages = await env.CONFIG.get('messages', 'json') || [];
        return jsonResponse({ messages }, 200, origin);
      } catch (err) {
        return jsonResponse({ messages: [] }, 200, origin);
      }
    }

    // --- POST /messages/delete — admin only, deletes a message ---
    if (path === '/messages/delete' && request.method === 'POST') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const { id } = await request.json();
        let messages = await env.CONFIG.get('messages', 'json') || [];
        messages = messages.filter(m => m.id !== id);
        await env.CONFIG.put('messages', JSON.stringify(messages));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed to delete', detail: err.message }, 500, origin);
      }
    }

    // --- POST /messages/read — admin only, marks a message as read ---
    if (path === '/messages/read' && request.method === 'POST') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const { id } = await request.json();
        let messages = await env.CONFIG.get('messages', 'json') || [];
        const msg = messages.find(m => m.id === id);
        if (msg) msg.read = true;
        await env.CONFIG.put('messages', JSON.stringify(messages));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed', detail: err.message }, 500, origin);
      }
    }

    // --- iCal proxy (existing) ---
    const site = url.searchParams.get('site');

    if (!site || !ICAL_FEEDS[site]) {
      return jsonResponse(
        { error: 'Invalid site. Use ?site=samavas or ?site=chhaya' },
        400, origin
      );
    }

    try {
      const response = await fetch(ICAL_FEEDS[site], {
        headers: { 'User-Agent': 'AhanaHillside-CalSync/1.0' },
      });

      if (!response.ok) {
        throw new Error(`Hipcamp returned ${response.status}`);
      }

      const icsText = await response.text();
      const events = parseIcal(icsText);
      const bookedDates = [...new Set(events.flatMap(e => e.dates))].sort();

      return new Response(
        JSON.stringify({ site, bookedDates, events, updatedAt: new Date().toISOString() }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders(origin),
            'Cache-Control': 'public, max-age=300',
          },
        }
      );
    } catch (err) {
      return jsonResponse(
        { error: 'Failed to fetch calendar', detail: err.message },
        502, origin
      );
    }
  },
};
