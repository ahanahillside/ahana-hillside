// Cloudflare Worker — Ahana Hillside API
// Handles: iCal calendar proxy, site configuration, admin authentication, messages, bookings, images, Stripe payments
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
  'mountain-view': {
    name: 'MOUNTAIN VIEW ROOM',
    type: 'Private Room · Sleeps 2 · Mountain Views',
    description: 'Wake up to stunning mountain views from this cosy private room. Perfect for couples or solo travellers looking for a budget-friendly stay.',
    basePrice: 85,
    extraGuestFee: 25,
    maxGuests: 2,
  },
  'garden-view': {
    name: 'GARDEN VIEW ROOM',
    type: 'Private Room · Sleeps 2 · Garden Views',
    description: 'A peaceful room overlooking the tropical garden. Surrounded by lush greenery, this room offers a tranquil retreat.',
    basePrice: 75,
    extraGuestFee: 20,
    maxGuests: 2,
  },
  'suite': {
    name: 'SUITE WITH GARDEN VIEW',
    type: 'Private Suite · Sleeps 4 · Garden Views',
    description: 'Our most spacious room option — a private suite with separate living area and garden views. Ideal for small families.',
    basePrice: 110,
    extraGuestFee: 30,
    maxGuests: 4,
  },
  currency: 'AUD',
  bookingAddons: [
    { id: 'washing', name: 'Washing', price: 15, description: 'Use of washing machine for one load', enabled: true },
    { id: 'dryer', name: 'Clothes Dryer', price: 10, description: 'Use of clothes dryer for one load', enabled: true },
    { id: 'airport-pickup', name: 'Airport Pickup', price: 50, description: 'Pickup from Cairns Airport to Ahana Hillside', enabled: true },
    { id: 'airport-drop', name: 'Airport Drop-off', price: 50, description: 'Drop-off from Ahana Hillside to Cairns Airport', enabled: true },
  ],
  promoCodes: {},
  rules: [
    'No parties allowed without prior permission',
    'No loud or open music',
    'All dogs must be kept on a leash when on the main campground',
  ],
  // Pricing policies (rooms only — campsites keep flat rates)
  weekendMarkup: 20,        // % surcharge on Fri & Sat nights (rooms only)
  holidayMarkup: 25,        // % surcharge on public holiday nights (rooms only)
  cancellationDays: 14,     // free cancellation cutoff (days before check-in)
  nonRefundableDiscount: 10, // % discount for non-refundable bookings
  otaMarkup: 15,            // % markup for OTA channel comparison
};

// --- Australian Public Holidays engine ---
// Easter calculation (Anonymous Gregorian algorithm)
function easterSunday(year) {
  const a = year % 19;
  const b = Math.floor(year / 100);
  const c = year % 100;
  const d = Math.floor(b / 4);
  const e = b % 4;
  const f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3);
  const h = (19 * a + b - d - g + 15) % 30;
  const i = Math.floor(c / 4);
  const k = c % 4;
  const l = (32 + 2 * e + 2 * i - h - k) % 7;
  const m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31);
  const day = ((h + l - 7 * m + 114) % 31) + 1;
  return new Date(year, month - 1, day);
}

// Next Monday on or after a date
function nextMonday(date) {
  const d = new Date(date);
  const day = d.getDay();
  if (day === 0) d.setDate(d.getDate() + 1);
  else if (day > 1) d.setDate(d.getDate() + (8 - day));
  return d;
}

// Format date as YYYY-MM-DD
function fmtDate(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return y + '-' + m + '-' + dd;
}

// Add days to a date
function addDays(date, n) {
  const d = new Date(date);
  d.setDate(d.getDate() + n);
  return d;
}

// Second Monday of a month
function secondMonday(year, month) {
  const d = new Date(year, month, 1);
  const day = d.getDay();
  const first = day === 1 ? 1 : (day === 0 ? 2 : 9 - day);
  return new Date(year, month, first + 7);
}

// First Monday of a month
function firstMonday(year, month) {
  const d = new Date(year, month, 1);
  const day = d.getDay();
  const first = day === 1 ? 1 : (day === 0 ? 2 : 9 - day);
  return new Date(year, month, first);
}

// Substitute: if holiday falls on Sat → Mon; if Sun → Mon
function substituteDay(year, month, day) {
  const d = new Date(year, month, day);
  const dow = d.getDay();
  if (dow === 6) return addDays(d, 2); // Sat → Mon
  if (dow === 0) return addDays(d, 1); // Sun → Mon
  return d;
}

// Generate all Australian public holidays for a given year (national + all states)
function getAustralianHolidays(year) {
  const holidays = [];
  const add = (date, name, scope) => {
    holidays.push({ date: fmtDate(date), name, scope });
  };

  // --- National holidays ---
  add(substituteDay(year, 0, 1), "New Year's Day", 'National');
  add(substituteDay(year, 0, 26), 'Australia Day', 'National');

  const easter = easterSunday(year);
  const goodFriday = addDays(easter, -2);
  const easterSaturday = addDays(easter, -1);
  const easterMonday = addDays(easter, 1);
  add(goodFriday, 'Good Friday', 'National');
  add(easterSaturday, 'Easter Saturday', 'National');
  add(easter, 'Easter Sunday', 'National');
  add(easterMonday, 'Easter Monday', 'National');

  // Anzac Day — 25 April (no substitute in most states if on weekend, but WA/NT sub Mon if Sun)
  add(new Date(year, 3, 25), 'Anzac Day', 'National');

  add(substituteDay(year, 11, 25), 'Christmas Day', 'National');
  // Boxing Day — 26 Dec. If Christmas is Sat (sub Mon 27), Boxing Day subs to Tue 28
  const xmas = new Date(year, 11, 25);
  const xmasDow = xmas.getDay();
  if (xmasDow === 5) {
    // Christmas Fri, Boxing Day Sat → Mon 28
    add(new Date(year, 11, 28), 'Boxing Day', 'National');
  } else if (xmasDow === 6) {
    // Christmas Sat → Mon 27, Boxing Day Sun → Tue 28
    add(new Date(year, 11, 28), 'Boxing Day', 'National');
  } else if (xmasDow === 0) {
    // Christmas Sun → Mon 27, Boxing Day Mon 26 stays
    add(new Date(year, 11, 26), 'Boxing Day', 'National');
  } else {
    add(substituteDay(year, 11, 26), 'Boxing Day', 'National');
  }

  // --- ACT ---
  add(secondMonday(year, 2), 'Canberra Day', 'ACT');
  add(new Date(year, 4, 27), 'Reconciliation Day', 'ACT'); // 27 May or nearest Mon
  // Family & Community Day — last Mon before or on Sep 30 (now called "day off for the King's Birthday" region-adjusted)

  // --- NSW ---
  // Bank Holiday (not a public holiday for most workers, skip)

  // --- NT ---
  add(firstMonday(year, 4), 'May Day', 'NT');
  // Picnic Day — first Monday in August
  add(firstMonday(year, 7), 'Picnic Day', 'NT');

  // --- QLD ---
  // Royal Queensland Show (Brisbane only, skip — regional)

  // --- SA ---
  // Adelaide Cup — second Monday in March
  add(secondMonday(year, 2), 'Adelaide Cup', 'SA');
  // Proclamation Day — last Mon before or on 26 Dec (usually 24 Dec area)

  // --- TAS ---
  // Royal Hobart Regatta — second Monday in February (southern Tas only)
  add(secondMonday(year, 1), 'Royal Hobart Regatta', 'TAS');

  // --- VIC ---
  // Melbourne Cup — first Tuesday in November (metro only)
  const nov1 = new Date(year, 10, 1);
  const nov1dow = nov1.getDay();
  const melbCupDay = 1 + ((2 - nov1dow + 7) % 7);
  add(new Date(year, 10, melbCupDay), 'Melbourne Cup', 'VIC');

  // --- WA ---
  // Western Australia Day — 1 June
  add(substituteDay(year, 5, 1), 'Western Australia Day', 'WA');

  // --- King's/Queen's Birthday (varies by state) ---
  // ACT, NSW, SA, TAS — second Monday in June
  add(secondMonday(year, 5), "King's Birthday", 'ACT/NSW/SA/TAS');
  // QLD — last Monday in October
  const oct31 = new Date(year, 9, 31);
  const oct31dow = oct31.getDay();
  const lastMonOct = oct31dow === 1 ? oct31 : new Date(year, 9, 31 - ((oct31dow + 6) % 7));
  add(lastMonOct, "King's Birthday", 'QLD');
  // VIC — second Monday in June (same as above group)
  add(secondMonday(year, 5), "King's Birthday", 'VIC');
  // WA — last Monday in September
  const sep30 = new Date(year, 8, 30);
  const sep30dow = sep30.getDay();
  const lastMonSep = sep30dow === 1 ? sep30 : new Date(year, 8, 30 - ((sep30dow + 6) % 7));
  add(lastMonSep, "King's Birthday", 'WA');
  // NT — second Monday in June
  add(secondMonday(year, 5), "King's Birthday", 'NT');

  return holidays;
}

const DEFAULT_PASSWORD = 'ahana2026';
const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB per image
const MAX_IMAGES_PER_SITE = 15;
const SITE_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const SITE_VIDEO_TYPES = ['video/mp4', 'video/webm', 'video/quicktime'];
const MAX_GALLERY_ITEMS = 50;
const MAX_VIDEO_SIZE = 50 * 1024 * 1024; // 50MB per video
const GALLERY_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const GALLERY_VIDEO_TYPES = ['video/mp4', 'video/webm', 'video/quicktime'];

const EXPLORE_SLOTS = ['neighbourhood', 'reef', 'rainforest', 'waterfall', 'tablelands', 'beach', 'cairns', 'kitchen'];

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

const RATE_LIMIT_MAX = 5;        // max failed attempts
const RATE_LIMIT_WINDOW = 900;   // 15-minute lockout (seconds)

async function checkRateLimit(ip, env) {
  try {
    const key = 'ratelimit:' + ip;
    const data = await env.CONFIG.get(key, 'json');
    if (!data) return { blocked: false };
    if (data.count >= RATE_LIMIT_MAX) {
      const elapsed = (Date.now() - data.firstAttempt) / 1000;
      if (elapsed < RATE_LIMIT_WINDOW) return { blocked: true };
    }
    return { blocked: false };
  } catch (e) { return { blocked: false }; }
}

async function recordFailedAttempt(ip, env) {
  try {
    const key = 'ratelimit:' + ip;
    const data = await env.CONFIG.get(key, 'json') || { count: 0, firstAttempt: Date.now() };
    const elapsed = (Date.now() - data.firstAttempt) / 1000;
    if (elapsed >= RATE_LIMIT_WINDOW) {
      // Window expired, start fresh
      await env.CONFIG.put(key, JSON.stringify({ count: 1, firstAttempt: Date.now() }), { expirationTtl: RATE_LIMIT_WINDOW });
    } else {
      data.count++;
      await env.CONFIG.put(key, JSON.stringify(data), { expirationTtl: RATE_LIMIT_WINDOW });
    }
  } catch (e) {}
}

async function clearRateLimit(ip, env) {
  try { await env.CONFIG.delete('ratelimit:' + ip); } catch (e) {}
}

async function verifyAuth(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '');
  const password = await getPassword(env);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Check rate limit before verifying
  const { blocked } = await checkRateLimit(ip, env);
  if (blocked) return { ok: false, rateLimited: true };

  if (token === password) {
    clearRateLimit(ip, env); // Reset on success
    return { ok: true, rateLimited: false };
  }

  await recordFailedAttempt(ip, env);
  return { ok: false, rateLimited: false };
}

// --- Image helpers ---
async function getImageList(env, site) {
  try {
    const list = await env.CONFIG.get(`images:${site}`, 'json');
    if (list) return list;
  } catch (e) {}
  return [];
}

// Helper: returns an error Response if auth fails, or null if OK
async function requireAuth(request, env, origin) {
  const auth = await verifyAuth(request, env);
  if (auth.rateLimited) return jsonResponse({ error: 'Too many failed attempts. Try again in 15 minutes.' }, 429, origin);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401, origin);
  return null;
}

async function saveImageList(env, site, list) {
  await env.CONFIG.put(`images:${site}`, JSON.stringify(list));
}

// --- Email notification helper ---
async function sendBookingEmail(env, booking) {
  try {
    const settings = await env.CONFIG.get('notification-settings', 'json');
    if (!settings || !settings.enabled || !settings.email || !settings.apiKey) return;

    const sym = { AUD: 'AU$', USD: 'US$', EUR: '€', GBP: '£' }[booking.currency] || 'AU$';

    const html = `
      <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px">
        <h2 style="color:#2C3E2D;margin-bottom:4px">New Booking Received</h2>
        <p style="color:#A69583;font-size:14px;margin-top:0">Ahana Hillside — ${booking.siteName || booking.site}</p>
        <hr style="border:none;border-top:1px solid #e8e0d8;margin:16px 0">
        <table style="width:100%;font-size:14px;border-collapse:collapse">
          <tr><td style="padding:6px 0;color:#A69583;width:120px">Guest</td><td style="padding:6px 0;color:#3D3D3D"><strong>${booking.name}</strong></td></tr>
          <tr><td style="padding:6px 0;color:#A69583">Email</td><td style="padding:6px 0"><a href="mailto:${booking.email}" style="color:#2C3E2D">${booking.email}</a></td></tr>
          <tr><td style="padding:6px 0;color:#A69583">Phone</td><td style="padding:6px 0"><a href="tel:${booking.phone}" style="color:#2C3E2D">${booking.phone}</a></td></tr>
          <tr><td style="padding:6px 0;color:#A69583">Campsite</td><td style="padding:6px 0;color:#3D3D3D">${booking.siteName || booking.site}</td></tr>
          <tr><td style="padding:6px 0;color:#A69583">Check-in</td><td style="padding:6px 0;color:#3D3D3D">${booking.checkin}</td></tr>
          <tr><td style="padding:6px 0;color:#A69583">Check-out</td><td style="padding:6px 0;color:#3D3D3D">${booking.checkout}</td></tr>
          <tr><td style="padding:6px 0;color:#A69583">Guests</td><td style="padding:6px 0;color:#3D3D3D">${booking.guests}</td></tr>
          <tr><td style="padding:6px 0;color:#A69583">Nights</td><td style="padding:6px 0;color:#3D3D3D">${booking.nights}</td></tr>
          <tr><td style="padding:6px 0;color:#A69583">Total</td><td style="padding:6px 0;color:#2C3E2D"><strong>${sym}${(booking.total || 0).toFixed(2)}</strong>${booking.promoCode ? ' (promo: ' + booking.promoCode + ')' : ''}</td></tr>
        </table>
        <hr style="border:none;border-top:1px solid #e8e0d8;margin:16px 0">
        <p style="font-size:13px;color:#A69583">View and manage this booking on your <a href="https://www.ahanahillside.com/admin" style="color:#2C3E2D">Admin Dashboard</a>.</p>
      </div>
    `;

    const fromEmail = settings.fromEmail || 'bookings@notifications.ahanahillside.com';

    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + settings.apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'Ahana Hillside <' + fromEmail + '>',
        to: [settings.email],
        subject: 'New Booking — ' + (booking.siteName || booking.site) + ' — ' + booking.name,
        html: html,
      }),
    });
  } catch (e) {
    // Non-blocking — don't fail the booking if email fails
  }
}

// --- Stripe helpers ---
async function getStripeSettings(env) {
  try {
    const s = await env.CONFIG.get('stripe-settings', 'json');
    if (s) return s;
  } catch (e) {}
  return { enabled: false, secretKey: '', webhookSecret: '' };
}

async function createCheckoutSession(secretKey, booking, siteUrl) {
  const currency = (booking.currency || 'AUD').toLowerCase();
  const amount = Math.round((booking.total || 0) * 100); // Stripe uses cents

  const params = new URLSearchParams();
  params.append('payment_method_types[]', 'card');
  params.append('line_items[0][price_data][currency]', currency);
  params.append('line_items[0][price_data][product_data][name]',
    (booking.siteName || booking.site) + ' — ' + booking.nights + ' night' + (booking.nights > 1 ? 's' : ''));
  params.append('line_items[0][price_data][product_data][description]',
    booking.checkin + ' to ' + booking.checkout + ' · ' + booking.guests + ' guest' + (booking.guests > 1 ? 's' : ''));
  params.append('line_items[0][price_data][unit_amount]', amount.toString());
  params.append('line_items[0][quantity]', '1');
  params.append('mode', 'payment');
  params.append('success_url', siteUrl + '/booking-confirmed');
  params.append('cancel_url', siteUrl + '/book');
  params.append('customer_email', booking.email);
  params.append('metadata[booking_id]', booking.id);

  const response = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + btoa(secretKey + ':'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  return await response.json();
}

async function verifyStripeSignature(payload, sigHeader, secret) {
  try {
    const elements = {};
    sigHeader.split(',').forEach(part => {
      const [key, ...rest] = part.split('=');
      elements[key.trim()] = rest.join('=');
    });

    const timestamp = elements.t;
    const signature = elements.v1;
    if (!timestamp || !signature) return false;

    const signedPayload = timestamp + '.' + payload;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
    const expected = Array.from(new Uint8Array(mac)).map(b => b.toString(16).padStart(2, '0')).join('');

    return expected === signature;
  } catch (e) {
    return false;
  }
}

export default {
  async fetch(request, env, ctx) {
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
      const stripe = await getStripeSettings(env);
      config.paymentsEnabled = stripe.enabled && !!stripe.secretKey;
      return jsonResponse(config, 200, origin, 'public, max-age=60');
    }

    // --- POST /config — admin only, updates site configuration ---
    if (path === '/config' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const newConfig = await request.json();
        await env.CONFIG.put('site-config', JSON.stringify(newConfig));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Invalid data', detail: err.message }, 400, origin);
      }
    }

    // --- GET /holidays — public, returns Australian public holidays for given year(s) ---
    if (path === '/holidays' && request.method === 'GET') {
      const url = new URL(request.url);
      const yearParam = url.searchParams.get('year');
      const currentYear = new Date().getFullYear();
      const years = yearParam ? yearParam.split(',').map(Number).filter(y => y >= 2020 && y <= 2050) : [currentYear, currentYear + 1];
      const holidays = [];
      for (const yr of years) {
        holidays.push(...getAustralianHolidays(yr));
      }
      // Deduplicate by date (same date can appear for multiple scopes)
      const seen = new Set();
      const unique = holidays.filter(h => {
        if (seen.has(h.date)) return false;
        seen.add(h.date);
        return true;
      });
      unique.sort((a, b) => a.date.localeCompare(b.date));
      return jsonResponse({ holidays: unique }, 200, origin, 'public, max-age=86400');
    }

    // --- POST /auth — login, returns token on success ---
    if (path === '/auth' && request.method === 'POST') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const { blocked } = await checkRateLimit(ip, env);
      if (blocked) {
        return jsonResponse({ error: 'Too many failed attempts. Try again in 15 minutes.' }, 429, origin);
      }
      try {
        const { password } = await request.json();
        const stored = await getPassword(env);
        if (password === stored) {
          await clearRateLimit(ip, env);
          return jsonResponse({ success: true, token: stored }, 200, origin);
        }
        await recordFailedAttempt(ip, env);
        return jsonResponse({ error: 'Invalid password' }, 401, origin);
      } catch (err) {
        return jsonResponse({ error: 'Invalid request' }, 400, origin);
      }
    }

    // --- POST /password — admin only, changes admin password ---
    if (path === '/password' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
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
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const messages = await env.CONFIG.get('messages', 'json') || [];
        return jsonResponse({ messages }, 200, origin);
      } catch (err) {
        return jsonResponse({ messages: [] }, 200, origin);
      }
    }

    // --- POST /messages/delete — admin only, deletes a message ---
    if (path === '/messages/delete' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
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
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
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
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const formData = await request.formData();
        const site = formData.get('site');
        const file = formData.get('file');

        if (!site || !['samavas', 'chhaya', 'mountain-view', 'garden-view', 'suite'].includes(site)) {
          return jsonResponse({ error: 'Invalid site' }, 400, origin);
        }
        if (!file || !(file instanceof File)) {
          return jsonResponse({ error: 'No file provided' }, 400, origin);
        }

        // Validate file type
        const isImage = SITE_IMAGE_TYPES.includes(file.type);
        const isVideo = SITE_VIDEO_TYPES.includes(file.type);
        if (!isImage && !isVideo) {
          return jsonResponse({ error: 'Only JPEG, PNG, WebP images and MP4, WebM, MOV videos are allowed' }, 400, origin);
        }

        // Validate file size
        const maxSize = isVideo ? MAX_VIDEO_SIZE : MAX_IMAGE_SIZE;
        if (file.size > maxSize) {
          return jsonResponse({ error: isVideo ? 'Video must be under 50MB' : 'Image must be under 5MB' }, 400, origin);
        }

        // Check image count limit
        const imageList = await getImageList(env, site);
        if (imageList.length >= MAX_IMAGES_PER_SITE) {
          return jsonResponse({ error: `Maximum ${MAX_IMAGES_PER_SITE} images per site` }, 400, origin);
        }

        // Generate unique ID
        const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

        // Store file binary in KV
        const mediaType = isVideo ? 'video' : 'image';
        const arrayBuffer = await file.arrayBuffer();
        await env.CONFIG.put(`image:${id}`, arrayBuffer, {
          metadata: { contentType: file.type, site, name: file.name, mediaType },
        });

        // Add to image list
        imageList.push({
          id,
          name: file.name,
          contentType: file.type,
          size: file.size,
          mediaType,
          uploadedAt: new Date().toISOString(),
        });
        await saveImageList(env, site, imageList);

        return jsonResponse({ success: true, id, index: imageList.length }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Upload failed', detail: err.message }, 500, origin);
      }
    }

    // --- GET /images/list/:site — public, returns image list for a site ---
    const listMatch = path.match(/^\/images\/list\/(samavas|chhaya|mountain-view|garden-view|suite)$/);
    if (listMatch && request.method === 'GET') {
      const site = listMatch[1];
      const imageList = await getImageList(env, site);
      return jsonResponse({ site, images: imageList }, 200, origin, 'public, max-age=60');
    }

    // --- GET /images/:site/:id — public, serves an image ---
    const imgMatch = path.match(/^\/images\/(samavas|chhaya|mountain-view|garden-view|suite)\/([a-z0-9]+)$/);
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
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const { site, id } = await request.json();
        if (!site || !['samavas', 'chhaya', 'mountain-view', 'garden-view', 'suite'].includes(site)) {
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
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const { site, order } = await request.json();
        if (!site || !['samavas', 'chhaya', 'mountain-view', 'garden-view', 'suite'].includes(site)) {
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

    // --- Gallery endpoints ---

    // POST /gallery/upload — admin only, upload image or video to gallery
    if (path === '/gallery/upload' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const formData = await request.formData();
        const file = formData.get('file');

        if (!file || !(file instanceof File)) {
          return jsonResponse({ error: 'No file provided' }, 400, origin);
        }

        const isImage = GALLERY_IMAGE_TYPES.includes(file.type);
        const isVideo = GALLERY_VIDEO_TYPES.includes(file.type);
        if (!isImage && !isVideo) {
          return jsonResponse({ error: 'Only JPEG, PNG, WebP images and MP4, WebM, MOV videos are allowed' }, 400, origin);
        }

        const maxSize = isVideo ? MAX_VIDEO_SIZE : MAX_IMAGE_SIZE;
        if (file.size > maxSize) {
          return jsonResponse({ error: isVideo ? 'Video must be under 50MB' : 'Image must be under 5MB' }, 400, origin);
        }

        const galleryList = await env.CONFIG.get('gallery-items', 'json') || [];
        if (galleryList.length >= MAX_GALLERY_ITEMS) {
          return jsonResponse({ error: 'Maximum ' + MAX_GALLERY_ITEMS + ' gallery items' }, 400, origin);
        }

        const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        const arrayBuffer = await file.arrayBuffer();
        await env.CONFIG.put('gallery:' + id, arrayBuffer, {
          metadata: { contentType: file.type, name: file.name, type: isVideo ? 'video' : 'image' },
        });

        galleryList.push({
          id,
          name: file.name,
          contentType: file.type,
          mediaType: isVideo ? 'video' : 'image',
          size: file.size,
          uploadedAt: new Date().toISOString(),
        });
        await env.CONFIG.put('gallery-items', JSON.stringify(galleryList));

        return jsonResponse({ success: true, id, mediaType: isVideo ? 'video' : 'image' }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Upload failed', detail: err.message }, 500, origin);
      }
    }

    // GET /gallery/list — public, returns gallery items
    if (path === '/gallery/list' && request.method === 'GET') {
      const galleryList = await env.CONFIG.get('gallery-items', 'json') || [];
      return jsonResponse({ items: galleryList }, 200, origin, 'public, max-age=60');
    }

    // GET /gallery/:id — public, serves a gallery file
    const galleryMatch = path.match(/^\/gallery\/([a-z0-9]+)$/);
    if (galleryMatch && request.method === 'GET') {
      const gId = galleryMatch[1];
      try {
        const { value, metadata } = await env.CONFIG.getWithMetadata('gallery:' + gId, 'arrayBuffer');
        if (!value) {
          return new Response('Not found', { status: 404, headers: corsHeaders(origin) });
        }
        return new Response(value, {
          status: 200,
          headers: {
            'Content-Type': metadata?.contentType || 'application/octet-stream',
            'Cache-Control': 'public, max-age=86400',
            ...corsHeaders(origin),
          },
        });
      } catch (err) {
        return new Response('Not found', { status: 404, headers: corsHeaders(origin) });
      }
    }

    // POST /gallery/delete — admin only, deletes a gallery item
    if (path === '/gallery/delete' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const { id } = await request.json();
        let galleryList = await env.CONFIG.get('gallery-items', 'json') || [];
        galleryList = galleryList.filter(item => item.id !== id);
        await env.CONFIG.put('gallery-items', JSON.stringify(galleryList));
        await env.CONFIG.delete('gallery:' + id);
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Delete failed', detail: err.message }, 500, origin);
      }
    }

    // POST /gallery/reorder — admin only, reorders gallery items
    if (path === '/gallery/reorder' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const { order } = await request.json();
        if (!Array.isArray(order)) {
          return jsonResponse({ error: 'Order must be an array of IDs' }, 400, origin);
        }
        const galleryList = await env.CONFIG.get('gallery-items', 'json') || [];
        const byId = {};
        galleryList.forEach(item => { byId[item.id] = item; });
        const newList = order.filter(id => byId[id]).map(id => byId[id]);
        galleryList.forEach(item => { if (!order.includes(item.id)) newList.push(item); });
        await env.CONFIG.put('gallery-items', JSON.stringify(newList));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Reorder failed', detail: err.message }, 500, origin);
      }
    }

    // --- Homepage background endpoints ---

    // GET /homepage-bg/info — public, returns background metadata
    if (path === '/homepage-bg/info' && request.method === 'GET') {
      try {
        const meta = await env.CONFIG.get('homepage-bg-meta', 'json');
        if (meta) return jsonResponse({ exists: true, mediaType: meta.mediaType, contentType: meta.contentType }, 200, origin, 'public, max-age=60');
        return jsonResponse({ exists: false }, 200, origin, 'public, max-age=60');
      } catch (e) {
        return jsonResponse({ exists: false }, 200, origin);
      }
    }

    // GET /homepage-bg — public, serves the background file
    if (path === '/homepage-bg' && request.method === 'GET') {
      try {
        const { value, metadata } = await env.CONFIG.getWithMetadata('homepage-bg-file', 'arrayBuffer');
        if (!value) return new Response('Not found', { status: 404, headers: corsHeaders(origin) });
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

    // POST /homepage-bg/upload — admin only, upload a new homepage background
    if (path === '/homepage-bg/upload' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const formData = await request.formData();
        const file = formData.get('file');

        if (!file || !(file instanceof File)) {
          return jsonResponse({ error: 'No file provided' }, 400, origin);
        }

        const isImage = GALLERY_IMAGE_TYPES.includes(file.type);
        const isVideo = GALLERY_VIDEO_TYPES.includes(file.type);
        if (!isImage && !isVideo) {
          return jsonResponse({ error: 'Only JPEG, PNG, WebP images and MP4, WebM, MOV videos are allowed' }, 400, origin);
        }

        const maxSize = isVideo ? MAX_VIDEO_SIZE : MAX_IMAGE_SIZE;
        if (file.size > maxSize) {
          return jsonResponse({ error: isVideo ? 'Video must be under 50MB' : 'Image must be under 5MB' }, 400, origin);
        }

        const arrayBuffer = await file.arrayBuffer();
        const mediaType = isVideo ? 'video' : 'image';

        await env.CONFIG.put('homepage-bg-file', arrayBuffer, {
          metadata: { contentType: file.type, mediaType, name: file.name },
        });
        await env.CONFIG.put('homepage-bg-meta', JSON.stringify({
          mediaType, contentType: file.type, name: file.name, size: file.size, uploadedAt: new Date().toISOString(),
        }));

        return jsonResponse({ success: true, mediaType }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Upload failed', detail: err.message }, 500, origin);
      }
    }

    // POST /homepage-bg/delete — admin only, remove custom background
    if (path === '/homepage-bg/delete' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        await env.CONFIG.delete('homepage-bg-file');
        await env.CONFIG.delete('homepage-bg-meta');
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Delete failed', detail: err.message }, 500, origin);
      }
    }

    // --- Camping experience background endpoints ---

    // GET /campsite-bg/info — public, returns background metadata
    if (path === '/campsite-bg/info' && request.method === 'GET') {
      try {
        const meta = await env.CONFIG.get('campsite-bg-meta', 'json');
        if (meta) return jsonResponse({ exists: true, mediaType: meta.mediaType, contentType: meta.contentType }, 200, origin, 'public, max-age=60');
        return jsonResponse({ exists: false }, 200, origin, 'public, max-age=60');
      } catch (e) {
        return jsonResponse({ exists: false }, 200, origin);
      }
    }

    // GET /campsite-bg — public, serves the camping experience background
    if (path === '/campsite-bg' && request.method === 'GET') {
      try {
        const { value, metadata } = await env.CONFIG.getWithMetadata('campsite-bg-file', 'arrayBuffer');
        if (!value) return new Response('Not found', { status: 404, headers: corsHeaders(origin) });
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

    // POST /campsite-bg/upload — admin only, upload camping experience background
    if (path === '/campsite-bg/upload' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const formData = await request.formData();
        const file = formData.get('file');

        if (!file || !(file instanceof File)) {
          return jsonResponse({ error: 'No file provided' }, 400, origin);
        }

        const isImage = GALLERY_IMAGE_TYPES.includes(file.type);
        const isVideo = GALLERY_VIDEO_TYPES.includes(file.type);
        if (!isImage && !isVideo) {
          return jsonResponse({ error: 'Only JPEG, PNG, WebP images and MP4, WebM, MOV videos are allowed' }, 400, origin);
        }

        const maxSize = isVideo ? MAX_VIDEO_SIZE : MAX_IMAGE_SIZE;
        if (file.size > maxSize) {
          return jsonResponse({ error: isVideo ? 'Video must be under 50MB' : 'Image must be under 5MB' }, 400, origin);
        }

        const arrayBuffer = await file.arrayBuffer();
        const mediaType = isVideo ? 'video' : 'image';

        await env.CONFIG.put('campsite-bg-file', arrayBuffer, {
          metadata: { contentType: file.type, mediaType, name: file.name },
        });
        await env.CONFIG.put('campsite-bg-meta', JSON.stringify({
          mediaType, contentType: file.type, name: file.name, size: file.size, uploadedAt: new Date().toISOString(),
        }));

        return jsonResponse({ success: true, mediaType }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Upload failed', detail: err.message }, 500, origin);
      }
    }

    // POST /campsite-bg/delete — admin only, remove camping experience background
    if (path === '/campsite-bg/delete' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        await env.CONFIG.delete('campsite-bg-file');
        await env.CONFIG.delete('campsite-bg-meta');
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Delete failed', detail: err.message }, 500, origin);
      }
    }

    // --- Explore section image endpoints ---

    // GET /explore/list — public, returns metadata for all explore slots
    if (path === '/explore/list' && request.method === 'GET') {
      try {
        const data = await env.CONFIG.get('explore-images', 'json') || {};
        return jsonResponse({ slots: data }, 200, origin, 'public, max-age=60');
      } catch (e) {
        return jsonResponse({ slots: {} }, 200, origin);
      }
    }

    // GET /explore/:slot — public, serves the image/video for a slot
    const exploreMatch = path.match(/^\/explore\/(neighbourhood|reef|rainforest|waterfall|tablelands|beach|cairns|kitchen)$/);
    if (exploreMatch && request.method === 'GET') {
      const slot = exploreMatch[1];
      try {
        const { value, metadata } = await env.CONFIG.getWithMetadata('explore:' + slot, 'arrayBuffer');
        if (!value) return new Response('Not found', { status: 404, headers: corsHeaders(origin) });
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

    // POST /explore/upload — admin only, upload image/video for a specific slot
    if (path === '/explore/upload' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const formData = await request.formData();
        const file = formData.get('file');
        const slot = formData.get('slot');

        if (!slot || !EXPLORE_SLOTS.includes(slot)) {
          return jsonResponse({ error: 'Invalid slot. Use: ' + EXPLORE_SLOTS.join(', ') }, 400, origin);
        }
        if (!file || !(file instanceof File)) {
          return jsonResponse({ error: 'No file provided' }, 400, origin);
        }

        const isImage = GALLERY_IMAGE_TYPES.includes(file.type);
        const isVideo = GALLERY_VIDEO_TYPES.includes(file.type);
        if (!isImage && !isVideo) {
          return jsonResponse({ error: 'Only JPEG, PNG, WebP images and MP4, WebM, MOV videos are allowed' }, 400, origin);
        }

        const maxSize = isVideo ? MAX_VIDEO_SIZE : MAX_IMAGE_SIZE;
        if (file.size > maxSize) {
          return jsonResponse({ error: isVideo ? 'Video must be under 50MB' : 'Image must be under 5MB' }, 400, origin);
        }

        const arrayBuffer = await file.arrayBuffer();
        const mediaType = isVideo ? 'video' : 'image';

        await env.CONFIG.put('explore:' + slot, arrayBuffer, {
          metadata: { contentType: file.type, mediaType, name: file.name },
        });

        // Update slot metadata
        const data = await env.CONFIG.get('explore-images', 'json') || {};
        data[slot] = { mediaType, contentType: file.type, name: file.name, size: file.size, uploadedAt: new Date().toISOString() };
        await env.CONFIG.put('explore-images', JSON.stringify(data));

        return jsonResponse({ success: true, slot, mediaType }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Upload failed', detail: err.message }, 500, origin);
      }
    }

    // POST /explore/delete — admin only, remove an explore slot image
    if (path === '/explore/delete' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const { slot } = await request.json();
        if (!slot || !EXPLORE_SLOTS.includes(slot)) {
          return jsonResponse({ error: 'Invalid slot' }, 400, origin);
        }
        await env.CONFIG.delete('explore:' + slot);
        const data = await env.CONFIG.get('explore-images', 'json') || {};
        delete data[slot];
        await env.CONFIG.put('explore-images', JSON.stringify(data));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Delete failed', detail: err.message }, 500, origin);
      }
    }

    // --- POST /bookings — public, creates a new booking ---
    if (path === '/bookings' && request.method === 'POST') {
      try {
        const b = await request.json();
        if (!b.site || !['samavas', 'chhaya', 'mountain-view', 'garden-view', 'suite'].includes(b.site)) {
          return jsonResponse({ error: 'Invalid site' }, 400, origin);
        }
        if (!b.name || !b.email || !b.phone || !b.checkin || !b.checkout) {
          return jsonResponse({ error: 'Name, email, phone, check-in and check-out are required' }, 400, origin);
        }

        let bookings = [];
        try {
          const stored = await env.CONFIG.get('bookings', 'json');
          if (stored) bookings = stored;
        } catch (e) {}

        bookings.unshift({
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
          site: b.site,
          siteName: b.site.toUpperCase(),
          checkin: b.checkin.slice(0, 10),
          checkout: b.checkout.slice(0, 10),
          guests: parseInt(b.guests) || 2,
          name: b.name.slice(0, 200),
          email: b.email.slice(0, 200),
          phone: b.phone.slice(0, 50),
          nights: parseInt(b.nights) || 1,
          baseCost: parseFloat(b.baseCost) || 0,
          extraCost: parseFloat(b.extraCost) || 0,
          promoCode: (b.promoCode || '').slice(0, 50),
          discount: parseFloat(b.discount) || 0,
          total: parseFloat(b.total) || 0,
          currency: (b.currency || 'AUD').slice(0, 5),
          cancellationPolicy: ['flexible', 'non-refundable'].includes(b.cancellationPolicy) ? b.cancellationPolicy : 'flexible',
          addons: b.addons || {},
          addonsCost: parseFloat(b.addonsCost) || 0,
          status: 'pending',
          date: new Date().toISOString(),
        });

        if (bookings.length > 500) bookings = bookings.slice(0, 500);

        await env.CONFIG.put('bookings', JSON.stringify(bookings));

        const newBooking = bookings[0];

        // Check if Stripe payments are enabled
        const stripe = await getStripeSettings(env);
        if (stripe.enabled && stripe.secretKey && newBooking.total > 0) {
          try {
            const siteUrl = origin || 'https://www.ahanahillside.com';
            const session = await createCheckoutSession(stripe.secretKey, newBooking, siteUrl);
            if (session.url) {
              return jsonResponse({ success: true, checkout_url: session.url }, 200, origin);
            }
          } catch (stripeErr) {
            // Stripe failed — fall through to normal booking flow
          }
        }

        // No Stripe (or Stripe failed) — send email notification
        ctx.waitUntil(sendBookingEmail(env, newBooking));

        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed to save booking', detail: err.message }, 500, origin);
      }
    }

    // --- GET /bookings — admin only, returns all bookings ---
    if (path === '/bookings' && request.method === 'GET') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const bookings = await env.CONFIG.get('bookings', 'json') || [];
        return jsonResponse({ bookings }, 200, origin);
      } catch (err) {
        return jsonResponse({ bookings: [] }, 200, origin);
      }
    }

    // --- POST /bookings/status — admin only, updates booking status ---
    if (path === '/bookings/status' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const { id, status } = await request.json();
        const validStatuses = ['pending', 'confirmed', 'cancelled', 'completed'];
        if (!validStatuses.includes(status)) {
          return jsonResponse({ error: 'Invalid status' }, 400, origin);
        }
        let bookings = await env.CONFIG.get('bookings', 'json') || [];
        const booking = bookings.find(b => b.id === id);
        if (booking) {
          booking.status = status;
          booking.updatedAt = new Date().toISOString();
        }
        await env.CONFIG.put('bookings', JSON.stringify(bookings));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed', detail: err.message }, 500, origin);
      }
    }

    // --- POST /bookings/delete — admin only, deletes a booking ---
    if (path === '/bookings/delete' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const { id } = await request.json();
        let bookings = await env.CONFIG.get('bookings', 'json') || [];
        bookings = bookings.filter(b => b.id !== id);
        await env.CONFIG.put('bookings', JSON.stringify(bookings));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed to delete', detail: err.message }, 500, origin);
      }
    }

    // --- POST /stripe-webhook — Stripe calls this after payment ---
    if (path === '/stripe-webhook' && request.method === 'POST') {
      try {
        const stripe = await getStripeSettings(env);
        if (!stripe.webhookSecret) {
          return jsonResponse({ error: 'Webhook not configured' }, 400, origin);
        }

        const payload = await request.text();
        const sigHeader = request.headers.get('stripe-signature') || '';

        const valid = await verifyStripeSignature(payload, sigHeader, stripe.webhookSecret);
        if (!valid) {
          return jsonResponse({ error: 'Invalid signature' }, 400, origin);
        }

        const event = JSON.parse(payload);

        if (event.type === 'checkout.session.completed') {
          const session = event.data.object;
          const bookingId = session.metadata?.booking_id;

          if (bookingId) {
            let bookings = await env.CONFIG.get('bookings', 'json') || [];
            const booking = bookings.find(b => b.id === bookingId);
            if (booking) {
              booking.status = 'confirmed';
              booking.paidAt = new Date().toISOString();
              booking.stripeSessionId = session.id;
              booking.stripePaymentAmount = session.amount_total;
              await env.CONFIG.put('bookings', JSON.stringify(bookings));

              // Send email notification (non-blocking)
              ctx.waitUntil(sendBookingEmail(env, booking));
            }
          }
        }

        return jsonResponse({ received: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Webhook failed', detail: err.message }, 500, origin);
      }
    }

    // --- GET /stripe-settings — admin only, returns masked Stripe config ---
    if (path === '/stripe-settings' && request.method === 'GET') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const settings = await getStripeSettings(env);
        // Never send full secret keys to the browser
        return jsonResponse({ settings: {
          enabled: settings.enabled,
          hasSecretKey: !!settings.secretKey,
          maskedSecretKey: settings.secretKey ? settings.secretKey.slice(0, 7) + '...' + settings.secretKey.slice(-4) : '',
          hasWebhookSecret: !!settings.webhookSecret,
          maskedWebhookSecret: settings.webhookSecret ? settings.webhookSecret.slice(0, 7) + '...' + settings.webhookSecret.slice(-4) : '',
        } }, 200, origin);
      } catch (err) {
        return jsonResponse({ settings: { enabled: false, hasSecretKey: false, maskedSecretKey: '', hasWebhookSecret: false, maskedWebhookSecret: '' } }, 200, origin);
      }
    }

    // --- POST /stripe-settings — admin only, saves Stripe config ---
    if (path === '/stripe-settings' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const body = await request.json();
        const existing = await getStripeSettings(env);
        const settings = {
          enabled: !!body.enabled,
          // Preserve existing key if no new one provided
          secretKey: body.secretKey ? (body.secretKey).slice(0, 300) : existing.secretKey,
          webhookSecret: body.webhookSecret ? (body.webhookSecret).slice(0, 300) : existing.webhookSecret,
        };
        await env.CONFIG.put('stripe-settings', JSON.stringify(settings));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed to save', detail: err.message }, 500, origin);
      }
    }

    // --- GET /notification-settings — admin only, returns masked notification config ---
    if (path === '/notification-settings' && request.method === 'GET') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const settings = await env.CONFIG.get('notification-settings', 'json') || {
          enabled: false, email: '', apiKey: '', fromEmail: '',
        };
        // Never send full API key to the browser
        return jsonResponse({ settings: {
          enabled: settings.enabled,
          email: settings.email,
          hasApiKey: !!settings.apiKey,
          maskedApiKey: settings.apiKey ? settings.apiKey.slice(0, 5) + '...' + settings.apiKey.slice(-4) : '',
          fromEmail: settings.fromEmail,
        } }, 200, origin);
      } catch (err) {
        return jsonResponse({ settings: { enabled: false, email: '', hasApiKey: false, maskedApiKey: '', fromEmail: '' } }, 200, origin);
      }
    }

    // --- POST /notification-settings — admin only, saves notification config ---
    if (path === '/notification-settings' && request.method === 'POST') {
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const body = await request.json();
        const existing = await env.CONFIG.get('notification-settings', 'json') || {
          enabled: false, email: '', apiKey: '', fromEmail: '',
        };
        const settings = {
          enabled: !!body.enabled,
          email: (body.email || '').slice(0, 200),
          // Preserve existing API key if no new one provided
          apiKey: body.apiKey ? (body.apiKey).slice(0, 200) : existing.apiKey,
          fromEmail: (body.fromEmail || '').slice(0, 200),
        };
        await env.CONFIG.put('notification-settings', JSON.stringify(settings));
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: 'Failed to save', detail: err.message }, 500, origin);
      }
    }

    // --- GET /calendar/:site.ics — public, iCal feed for Hipcamp to import ---
    const calMatch = path.match(/^\/calendar\/(samavas|chhaya|mountain-view|garden-view|suite)\.ics$/);
    if (calMatch && request.method === 'GET') {
      const calSite = calMatch[1];
      try {
        // Gather blocked dates
        let blockedDates = [];
        try {
          blockedDates = await env.CONFIG.get(`blocked-dates:${calSite}`, 'json') || [];
        } catch (e) {}

        // Gather confirmed bookings
        let bookings = [];
        try {
          const stored = await env.CONFIG.get('bookings', 'json');
          if (stored) bookings = stored.filter(b =>
            b.site === calSite && (b.status === 'confirmed' || b.status === 'completed')
          );
        } catch (e) {}

        // Collect all blocked dates from bookings
        const bookingDates = new Set();
        bookings.forEach(b => {
          const start = new Date(b.checkin);
          const end = new Date(b.checkout);
          const cur = new Date(start);
          while (cur < end) {
            bookingDates.add(cur.toISOString().split('T')[0]);
            cur.setDate(cur.getDate() + 1);
          }
        });

        // Merge all unavailable dates
        const allDates = [...new Set([...blockedDates, ...bookingDates])].sort();

        // Build iCal
        let ical = 'BEGIN:VCALENDAR\r\n';
        ical += 'VERSION:2.0\r\n';
        ical += 'PRODID:-//Ahana Hillside//Calendar//EN\r\n';
        ical += 'CALSCALE:GREGORIAN\r\n';
        ical += 'METHOD:PUBLISH\r\n';
        ical += 'X-WR-CALNAME:' + calSite.toUpperCase() + '\r\n';

        // Group consecutive dates into single events
        let i = 0;
        while (i < allDates.length) {
          const startDate = allDates[i];
          let endDate = startDate;
          while (i + 1 < allDates.length) {
            const next = allDates[i + 1];
            const cur = new Date(endDate);
            cur.setDate(cur.getDate() + 1);
            if (cur.toISOString().split('T')[0] === next) {
              endDate = next;
              i++;
            } else break;
          }

          // DTEND is exclusive in iCal, so add one day
          const dtstart = startDate.replace(/-/g, '');
          const endD = new Date(endDate);
          endD.setDate(endD.getDate() + 1);
          const dtend = endD.toISOString().split('T')[0].replace(/-/g, '');

          ical += 'BEGIN:VEVENT\r\n';
          ical += 'DTSTART;VALUE=DATE:' + dtstart + '\r\n';
          ical += 'DTEND;VALUE=DATE:' + dtend + '\r\n';
          ical += 'SUMMARY:Unavailable\r\n';
          ical += 'UID:' + dtstart + '-' + calSite + '@ahanahillside.com\r\n';
          ical += 'END:VEVENT\r\n';
          i++;
        }

        ical += 'END:VCALENDAR\r\n';

        return new Response(ical, {
          status: 200,
          headers: {
            'Content-Type': 'text/calendar; charset=utf-8',
            'Cache-Control': 'public, max-age=300',
            ...corsHeaders(origin),
          },
        });
      } catch (err) {
        return new Response('Error generating calendar', {
          status: 500,
          headers: corsHeaders(origin),
        });
      }
    }

    // --- GET /blocked-dates/:site — public, returns manually blocked dates ---
    const blockedMatch = path.match(/^\/blocked-dates\/(samavas|chhaya|mountain-view|garden-view|suite)$/);
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
      { const authErr = await requireAuth(request, env, origin); if (authErr) return authErr; }
      try {
        const { site: bSite, dates } = await request.json();
        if (!bSite || !['samavas', 'chhaya', 'mountain-view', 'garden-view', 'suite'].includes(bSite)) {
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

    const ALL_VALID_SITES = ['samavas', 'chhaya', 'mountain-view', 'garden-view', 'suite'];
    if (!site || !ALL_VALID_SITES.includes(site)) {
      return jsonResponse(
        { error: 'Invalid site' },
        400, origin
      );
    }

    // Rooms don't have iCal feeds — return empty dates
    if (!ICAL_FEEDS[site]) {
      return jsonResponse({ site, bookedDates: [] }, 200, origin, 'public, max-age=300');
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
