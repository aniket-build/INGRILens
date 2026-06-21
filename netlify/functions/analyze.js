// Hardened Netlify function for Ingredient Lens
// Security: clients can ONLY request "extract" or "analyze" — they cannot
// choose the model, token limits, or prompts. This prevents abuse of your API key.

const ALLOWED_ORIGINS = [
  'https://ingrilens.netlify.app',
  'https://ingri-lens.netlify.app',
];

// ─── RATE LIMITING (in-memory, per IP) ───
// Resets on cold start — not perfectly durable, but blocks realistic abuse
// (one IP looping requests) without needing a database.
const HOUR_LIMIT = 10;
const DAY_LIMIT = 40;
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

// Module-level so it persists across invocations on a warm container
const requestLog = new Map(); // ip -> array of timestamps

function checkRateLimit(ip) {
  const now = Date.now();
  let timestamps = requestLog.get(ip) || [];
  // Drop anything older than 24h to keep memory bounded
  timestamps = timestamps.filter(t => now - t < DAY_MS);

  const lastHour = timestamps.filter(t => now - t < HOUR_MS).length;
  const lastDay = timestamps.length;

  if (lastHour >= HOUR_LIMIT) {
    return { allowed: false, reason: `Too many scans — limit is ${HOUR_LIMIT} per hour. Please try again shortly.` };
  }
  if (lastDay >= DAY_LIMIT) {
    return { allowed: false, reason: `Daily scan limit reached (${DAY_LIMIT}/day). Please try again tomorrow.` };
  }

  timestamps.push(now);
  requestLog.set(ip, timestamps);
  return { allowed: true };
}

const EXTRACT_PROMPT = "Extract ONLY the ingredient list from this product label image. Return just the raw ingredient text exactly as written on the label — nothing else. No commentary, no formatting, no headers. If you see multiple sections, only extract the ingredients/composition list. If you cannot read any ingredients, respond with exactly: UNREADABLE";

const ANALYSIS_PROMPT = `You are a world-class expert in food science, dermatology, cosmetic chemistry, and environmental toxicology. Analyze an ingredient list from a product.

STEP 1: Detect the product type: "food", "cosmetic", or "cleaning".
STEP 2: Analyze ALL ingredients concisely. Keep every text field SHORT — one tight sentence max per field. Be efficient, not verbose.

Return ONLY valid JSON (no markdown, no backticks):
{
  "product_type": "food"|"cosmetic"|"cleaning",
  "product_name_guess": "best guess product name",
  "product_summary": "1-2 short sentences",
  "health_score": <1-10>,
  "ingredients": [{"name":"...","category":"...","rating":"good|neutral|caution|bad","detail":"one short sentence"}],
  "emulsifiers_stabilizers": [{"name":"...","type":"emulsifier|stabilizer","detail":"one short sentence"}],
  "health_concerns": ["short phrase", "max 4 items"],
  "health_benefits": ["short phrase", "max 4 items"],
  "skin_impact": {"skin_types_suited":[],"skin_types_avoid":[],"irritation_risk":"low|moderate|high","comedogenic_risk":"low|moderate|high","allergen_flags":[],"long_term_concerns":["max 3 items"],"beneficial_actives":[]},
  "harsh_chemicals": [{"name":"...","concern":"one short sentence"}],
  "environmental_impact": {"eco_score":<1-10>,"biodegradability":"high|moderate|low","aquatic_toxicity_risk":"low|moderate|high","voc_level":"none|low|moderate|high","voc_details":"one short sentence","phosphate_free":true|false,"microplastic_risk":"none|low|moderate|high","packaging_note":"one short sentence or null"},
  "hazardous_chemicals": [{"name":"...","hazard_type":"irritant|corrosive|toxic|carcinogen|endocrine_disruptor|environmental_pollutant","detail":"one short sentence"}],
  "safety_precautions": ["short phrase", "max 4 items"],
  "better_alternatives": [{"instead_of":"ingredient","use":"safer alternative","why":"one short sentence"}],
  "recommendation": "1-2 short sentences"
}
Include only sections relevant to the product_type. Always include better_alternatives with 2-4 suggestions, max.
Categories for food: natural|preservative|emulsifier|stabilizer|colorant|sweetener|flavor_enhancer|thickener|antioxidant|acidity_regulator|other_additive|nutrient
Categories for cosmetic: active_ingredient|moisturizer|emollient|surfactant|preservative|fragrance|colorant|emulsifier|thickener|solvent|pH_adjuster|UV_filter|antioxidant|exfoliant|other
Categories for cleaning: surfactant|solvent|builder|bleach|enzyme|fragrance|preservative|colorant|pH_adjuster|chelating_agent|antimicrobial|thickener|propellant|other`;

exports.handler = async (event) => {
  const origin = event.headers.origin || event.headers.Origin || '';
  // CORS: only allow our own site (instead of '*' which lets any website use your key)
  const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  const cors = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: cors, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: cors, body: JSON.stringify({ error: { message: 'Method not allowed' } }) };
  }

  // Block browser requests from foreign origins
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    console.warn('Blocked foreign origin:', origin);
    return { statusCode: 403, headers: cors, body: JSON.stringify({ error: { message: 'Forbidden' } }) };
  }

  // ─── Rate limit by IP ───
  const clientIp = event.headers['x-nf-client-connection-ip']
    || (event.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || 'unknown';
  const rl = checkRateLimit(clientIp);
  if (!rl.allowed) {
    console.warn('Rate limit hit:', clientIp, rl.reason);
    return { statusCode: 429, headers: cors, body: JSON.stringify({ error: { message: rl.reason } }) };
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('ANTHROPIC_API_KEY not set');
    return { statusCode: 500, headers: cors, body: JSON.stringify({ error: { message: 'API key not configured on server.' } }) };
  }

  // Reject oversized payloads early (max ~2MB)
  if ((event.body?.length || 0) > 2_000_000) {
    return { statusCode: 413, headers: cors, body: JSON.stringify({ error: { message: 'Request too large. Use a smaller image.' } }) };
  }

  let req;
  try {
    req = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: { message: 'Invalid request format' } }) };
  }

  // ─── Build the Anthropic request SERVER-SIDE based on mode ───
  // The client can never choose models, prompts, or token limits.
  let anthropicBody;

  if (req.mode === 'extract') {
    // Sanitize base64: strip anything that isn't valid base64
    const img = String(req.image || '').replace(/[^A-Za-z0-9+/=]/g, '');
    if (!img || img.length < 100) {
      return { statusCode: 400, headers: cors, body: JSON.stringify({ error: { message: 'Invalid image data' } }) };
    }
    if (img.length > 1_800_000) {
      return { statusCode: 413, headers: cors, body: JSON.stringify({ error: { message: 'Image too large' } }) };
    }
    anthropicBody = {
      model: 'claude-haiku-4-5',
      max_tokens: 1500,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: img } },
          { type: 'text', text: EXTRACT_PROMPT },
        ],
      }],
    };
  } else if (req.mode === 'analyze') {
    const text = String(req.text || '').slice(0, 8000); // cap input length
    if (text.trim().length < 5) {
      return { statusCode: 400, headers: cors, body: JSON.stringify({ error: { message: 'Ingredient text too short' } }) };
    }
    anthropicBody = {
      model: 'claude-haiku-4-5',
      max_tokens: 2200,
      system: ANALYSIS_PROMPT,
      messages: [{ role: 'user', content: `Ingredient list from a product:\n\n${text}\n\nDetect type and analyze.` }],
    };
  } else {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: { message: 'Unknown mode' } }) };
  }

  try {
    console.log(`Mode: ${req.mode}, model: ${anthropicBody.model}`);
    const startTime = Date.now();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(anthropicBody),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    console.log(`Anthropic responded in ${Date.now() - startTime}ms, status: ${response.status}`);

    const responseText = await response.text();
    if (!responseText) {
      return { statusCode: 500, headers: cors, body: JSON.stringify({ error: { message: 'Empty response from AI. Try again.' } }) };
    }

    let data;
    try {
      data = JSON.parse(responseText);
    } catch {
      console.error('Non-JSON from Anthropic:', responseText.substring(0, 300));
      return { statusCode: 500, headers: cors, body: JSON.stringify({ error: { message: 'Invalid AI response. Try again.' } }) };
    }

    if (!response.ok) {
      console.error('Anthropic error:', response.status, JSON.stringify(data).substring(0, 300));
    }

    return { statusCode: response.status, headers: cors, body: JSON.stringify(data) };
  } catch (error) {
    console.error('Function error:', error.name, error.message);
    if (error.name === 'AbortError') {
      return { statusCode: 504, headers: cors, body: JSON.stringify({ error: { message: 'Analysis took too long. Please try again.' } }) };
    }
    return { statusCode: 500, headers: cors, body: JSON.stringify({ error: { message: error.message || 'Unknown error' } }) };
  }
};