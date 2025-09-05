router.post('/debugger/trees/main', async (req, res) => {
  try {
    let { codeInput } = req.body;

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(500).json({ error: 'API key is missing. Check your .env file.' });
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

   const prompt = `
You are a debugger for Trees data structures
Given the input code below, produce a JSON trace of its step-by-step execution.

Each step in the trace should be an object with this structure:

[
  {
    "event": "call",
    "description": "a very small and concise one line of the change in the current steps taking place"
    "func": "function_name",
    "args": { "param1": value },
    "depth": number,
    "visited": ["", "V", "", "V", …],      // an array of length N: put "V" at each visited index, "" otherwise
    "recStack": [/* nodes in recursion stack, or [] */],
     "queue": [/* node val in queue, or [] remeber it should give the only the current state of queue and values and not the previous  */],
    "adjacencyList": {
      "A": ["B", "C"],
      "B": ["D", "E"],
      "C": ["F", "G"]
    },
    "otherState": { /* any other algorithm-specific state, optional */ }
  },
  {
    "event": "return",
    "func": "function_name",
    "description": "a very small and concise one line of the change in the current steps taking place"
    "value": returnValue,
    "depth": number,
    "note": "base case reached",  // optional
    "visited": [/* nodes visited so far */],
    "recStack": [/* nodes in recursion stack, or [] */],
    "queue": [/* nodes in queue, or [] remeber it should give the only the current state of queue and values and not the previous  */],
   "adjacencyList": {
      "A": ["B", "C"],
      "B": ["D", "E"],
      "C": ["F", "G"]
    },
    "otherState": { /* any other algorithm-specific state, optional */ }
  }
]
In adjacencyList, provide the tree structure: for index 0, list its children, etc.
Only output valid JSON. No markdown, explanations, or extra text.

Input Code:
${codeInput}
`.trim();


    const apiResponse = await axios.post(
      endpoint,
      { contents: [{ parts: [{ text: prompt }] }] },
      { headers: { 'Content-Type': 'application/json' } }
    );

    const rawText = apiResponse.data?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!rawText) {
      return res.status(502).json({ error: 'Empty response from Gemini API.' });
    }

    const cleaned = rawText.replace(/```(?:json)?/g, '').trim();

    let trace;
    try {
      const sanitizedJson = sanitizeJsonString(cleaned);
      trace = JSON.parse(sanitizedJson);
    } catch (parseError) {
      console.error('JSON parse error:', parseError);
      return res.status(502).json({
        error: 'Failed to parse API response as JSON.',
        raw: rawText,
      });
    }

    return res.json({ trace });
  } catch (err) {
    console.error('Code analyzer error:', err.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to generate code analysis trace.' });
  }
});