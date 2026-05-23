// Netlify serverless function — keeps your API key safe
// Designed to give clear error messages so debugging is easier

exports.handler = async (event) => {
  console.log('=== Function invoked ===');
  console.log('Method:', event.httpMethod);
  console.log('Body length:', event.body?.length || 0);

  // CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
      },
      body: '',
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: { message: 'Method not allowed' } }),
    };
  }

  // Check API key
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('FATAL: ANTHROPIC_API_KEY not set in Netlify environment variables');
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({
        error: {
          message: 'API key not configured. Go to Netlify dashboard → Site settings → Environment variables → add ANTHROPIC_API_KEY',
        },
      }),
    };
  }

  console.log('API key found, length:', process.env.ANTHROPIC_API_KEY.length);

  try {
    console.log('Calling Anthropic API...');
    const startTime = Date.now();

    // Use AbortController for explicit timeout — 24s leaves buffer under 26s function limit
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 24000);

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: event.body,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    const elapsed = Date.now() - startTime;
    console.log(`Anthropic responded in ${elapsed}ms, status: ${response.status}`);

    // Read response as text first so we can handle non-JSON errors
    const responseText = await response.text();

    if (!responseText) {
      console.error('Anthropic returned empty body');
      return {
        statusCode: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
        body: JSON.stringify({
          error: { message: 'AI returned empty response. Please try again.' },
        }),
      };
    }

    // Try to parse as JSON
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseErr) {
      console.error('Failed to parse Anthropic response as JSON');
      console.error('Raw response:', responseText.substring(0, 500));
      return {
        statusCode: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
        body: JSON.stringify({
          error: { message: 'Invalid response from AI. Try again with a clearer image.' },
        }),
      };
    }

    if (!response.ok) {
      console.error('Anthropic API error:', JSON.stringify(data).substring(0, 500));
    } else {
      console.log('=== Success! ===');
    }

    return {
      statusCode: response.status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify(data),
    };
  } catch (error) {
    console.error('Function caught error:', error.name, error.message);

    if (error.name === 'AbortError') {
      return {
        statusCode: 504,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
        body: JSON.stringify({
          error: { message: 'Analysis took too long. Please try a smaller/clearer image or use manual entry.' },
        }),
      };
    }

    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({
        error: { message: error.message || 'Unknown error' },
      }),
    };
  }
};
