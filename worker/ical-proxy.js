// Cloudflare Worker — Ahana Hillside API
// Handles: iCal calendar proxy, site configuration, admin authentication, messages, images
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
const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB per image
const MAX_IMAGES_PER_SITE = 15;

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

// --- Image helpers ---
async function getImageList(env, site) {
  try {
    const list = await env.CONFIG.get(`images:${site}`, 'json');
    if (list) return list;
  } catch (e) {}
  return [];
}

async function saveImageList(env, site, list) {
  await env.CONFIG.put(`images:${site}`, JSON.stringify(list));
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

    // --- POST /images/upload — admin only, uploads an image for a site ---
    if (path === '/images/upload' && request.method === 'POST') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const formData = await request.formData();
        const site = formData.get('site');
        const file = formData.get('file');

        if (!site || !['samavas', 'chhaya'].includes(site)) {
          return jsonResponse({ error: 'Invalid site' }, 400, origin);
        }
        if (!file || !(file instanceof File)) {
          return jsonResponse({ error: 'No file provided' }, 400, origin);
        }

        // Validate file type
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(file.type)) {
          return jsonResponse({ error: 'Only JPEG, PNG, and WebP images are allowed' }, 400, origin);
        }

        // Validate file size
        if (file.size > MAX_IMAGE_SIZE) {
          return jsonResponse({ error: 'Image must be under 5MB' }, 400, origin);
        }

        // Check image count limit
        const imageList = await getImageList(env, site);
        if (imageList.length >= MAX_IMAGES_PER_SITE) {
          return jsonResponse({ error: `Maximum ${MAX_IMAGES_PER_SITE} images per site` }, 400, origin);
        }

        // Generate unique ID
        const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

        // Store image binary in KV
        const arrayBuffer = await file.arrayBuffer();
        await env.CONFIG.put(`image:${id}`, arrayBuffer, {
          metadata: { contentType: file.type, site, name: file.name },
        });

        // Add to image list
        imageList.push({
          id,
          name: file.name,
          contentType: file.type,
          size: file.size,
          uploadedAt: new Date().toISOString(),
        });
        await saveImageList(env, site, imageList);

        return jsonResponse({ success: true, id, index: imageList.length }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Upload failed', detail: err.message }, 500, origin);
      }
    }

    // --- GET /images/list/:site — public, returns image list for a site ---
    const listMatch = path.match(/^\/images\/list\/(samavas|chhaya)$/);
    if (listMatch && request.method === 'GET') {
      const site = listMatch[1];
      const imageList = await getImageList(env, site);
      return jsonResponse({ site, images: imageList }, 200, origin, 'public, max-age=60');
    }

    // --- GET /images/:site/:id — public, serves an image ---
    const imgMatch = path.match(/^\/images\/(samavas|chhaya)\/([a-z0-9]+)$/);
    if (imgMatch && request.method === 'GET') {
      const imgId = imgMatch[2];
      try {
        const { value, metadata } = await env.CONFIG.getWithMetadata(
          `image:${imgId}`,
          'arrayBuffer'
        );
        if (!value) {
          return new Response('Not found', { status: 404, headers: corsHeaders(origin) });
        }
        return new Response(value, {
          status: 200,
          headers: {
            'Content-Type': metadata?.contentType || 'image/jpeg',
            'Cache-Control': 'public, max-age=86400',
            ...corsHeaders(origin),
          },
        });
      } catch (err) {
        return new Response('Not found', { status: 404, headers: corsHeaders(origin) });
      }
    }

    // --- POST /images/delete — admin only, deletes an image ---
    if (path === '/images/delete' && request.method === 'POST') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const { site, id } = await request.json();
        if (!site || !['samavas', 'chhaya'].includes(site)) {
          return jsonResponse({ error: 'Invalid site' }, 400, origin);
        }

        // Remove from list
        let imageList = await getImageList(env, site);
        imageList = imageList.filter(img => img.id !== id);
        await saveImageList(env, site, imageList);

        // Delete binary
        await env.CONFIG.delete(`image:${id}`);

        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Delete failed', detail: err.message }, 500, origin);
      }
    }

    // --- POST /images/reorder — admin only, reorders images for a site ---
    if (path === '/images/reorder' && request.method === 'POST') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const { site, order } = await request.json();
        if (!site || !['samavas', 'chhaya'].includes(site)) {
          return jsonResponse({ error: 'Invalid site' }, 400, origin);
        }
        if (!Array.isArray(order)) {
          return jsonResponse({ error: 'Order must be an array of image IDs' }, 400, origin);
        }

        // Reorder: build new list based on provided order
        const imageList = await getImageList(env, site);
        const byId = {};
        imageList.forEach(img => { byId[img.id] = img; });

        const newList = order
          .filter(id => byId[id])
          .map(id => byId[id]);

        // Add any images not in the order array at the end
        imageList.forEach(img => {
          if (!order.includes(img.id)) newList.push(img);
        });

        await saveImageList(env, site, newList);
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Reorder failed', detail: err.message }, 500, origin);
      }
    }

    // --- GET /blocked-dates/:site — public, returns manually blocked dates ---
    const blockedMatch = path.match(/^\/blocked-dates\/(samavas|chhaya)$/);
    if (blockedMatch && request.method === 'GET') {
      const bSite = blockedMatch[1];
      try {
        const dates = await env.CONFIG.get(`blocked-dates:${bSite}`, 'json') || [];
        return jsonResponse({ site: bSite, blockedDates: dates }, 200, origin, 'public, max-age=30');
      } catch (e) {
        return jsonResponse({ site: bSite, blockedDates: [] }, 200, origin);
      }
    }

    // --- POST /blocked-dates — admin only, updates blocked dates for a site ---
    if (path === '/blocked-dates' && request.method === 'POST') {
      if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, origin);
      }
      try {
        const { site: bSite, dates } = await request.json();
        if (!bSite || !['samavas', 'chhaya'].includes(bSite)) {
          return jsonResponse({ error: 'Invalid site' }, 400, origin);
        }
        if (!Array.isArray(dates)) {
          return jsonResponse({ error: 'Dates must be an array of YYYY-MM-DD strings' }, 400, origin);
        }
        // Validate and deduplicate dates
        const validDates = [...new Set(dates.filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)))].sort();
        await env.CONFIG.put(`blocked-dates:${bSite}`, JSON.stringify(validDates));
        return jsonResponse({ success: true, count: validDates.length }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed to save', detail: err.message }, 500, origin);
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
      const hipcampDates = [...new Set(events.flatMap(e => e.dates))].sort();

      // Merge with manually blocked dates
      let manualDates = [];
      try {
        manualDates = await env.CONFIG.get(`blocked-dates:${site}`, 'json') || [];
      } catch (e) {}

      const bookedDates = [...new Set([...hipcampDates, ...manualDates])].sort();

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
