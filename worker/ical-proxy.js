// Cloudflare Worker — iCal proxy for Ahana Hillside
// Deploy: npx wrangler deploy worker/ical-proxy.js --name ahana-ical-proxy

const ICAL_FEEDS = {
  samavas: 'https://www.hipcamp.com/en-AU/bookings/cc06b2c9-7536-49df-a407-4bac49630d71/agenda.ics?cal=87645&s=940738',
  chhaya: 'https://www.hipcamp.com/en-AU/bookings/cc06b2c9-7536-49df-a407-4bac49630d71/agenda.ics?cal=87646&s=1103648',
};

const ALLOWED_ORIGINS = [
  'https://ahanahillside.github.io',
  'https://ahana-hillside.com',
  'https://www.ahana-hillside.com',
  'http://localhost',
  'http://127.0.0.1',
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.some(o => origin && origin.startsWith(o));
  return {
    'Access-Control-Allow-Origin': allowed ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'public, max-age=300',
  };
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

      // Build array of all dates in the range
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

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    const site = url.searchParams.get('site');

    if (!site || !ICAL_FEEDS[site]) {
      return new Response(
        JSON.stringify({ error: 'Invalid site. Use ?site=samavas or ?site=chhaya' }),
        { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } }
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

      // Flatten all booked dates into a single array
      const bookedDates = [...new Set(events.flatMap(e => e.dates))].sort();

      return new Response(
        JSON.stringify({ site, bookedDates, events, updatedAt: new Date().toISOString() }),
        { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } }
      );
    } catch (err) {
      return new Response(
        JSON.stringify({ error: 'Failed to fetch calendar', detail: err.message }),
        { status: 502, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } }
      );
    }
  },
};
