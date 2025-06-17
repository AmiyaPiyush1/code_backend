const express = require("express");
const router = express.Router();
const axios = require("axios");
const { AppError, ERROR_TYPES } = require('../../middleware/errorHandler');
const logger = require('../../config/logger');
const rateLimit = require('express-rate-limit');
require("dotenv").config();

// Enhanced configuration
const CONFIG = {
    EXECUTION_TIMEOUT: 5 * 60 * 1000, // 5 minutes
    MAX_REQUESTS_PER_MINUTE: 30,
    MAX_REQUESTS_PER_HOUR: 100,
    MAX_CODE_LENGTH: 10000, // characters
    MAX_RESPONSE_TOKENS: 2048,
    TEMPERATURE: 0.1,
    TOP_K: 40,
    TOP_P: 0.95,
    SUPPORTED_LANGUAGES: {
        javascript: { extension: 'js', comment: '//' },
        python: { extension: 'py', comment: '#' },
        java: { extension: 'java', comment: '//' },
        cpp: { extension: 'cpp', comment: '//' },
        csharp: { extension: 'cs', comment: '//' },
        php: { extension: 'php', comment: '//' },
        ruby: { extension: 'rb', comment: '#' },
        go: { extension: 'go', comment: '//' },
        rust: { extension: 'rs', comment: '//' },
        swift: { extension: 'swift', comment: '//' },
        kotlin: { extension: 'kt', comment: '//' }
    }
};

// Rate limiters
const minuteLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: CONFIG.MAX_REQUESTS_PER_MINUTE,
    message: { error: 'Too many requests per minute' },
    handler: (req, res, next) => {
        next(new AppError('Rate limit exceeded', 429, ERROR_TYPES.RATE_LIMIT));
    }
});

const hourLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: CONFIG.MAX_REQUESTS_PER_HOUR,
    message: { error: 'Too many requests per hour' },
    handler: (req, res, next) => {
        next(new AppError('Hourly rate limit exceeded', 429, ERROR_TYPES.RATE_LIMIT));
    }
});

// Execution state management
let isExecuting = false;
let executionTimeout = null;

// Enhanced execution state management
const setExecutionState = (state) => {
    try {
        isExecuting = state;
        if (state) {
            // Set a timeout to automatically stop execution
            executionTimeout = setTimeout(() => {
                isExecuting = false;
                logger.info("Execution automatically stopped after timeout");
            }, CONFIG.EXECUTION_TIMEOUT);
        } else if (executionTimeout) {
            clearTimeout(executionTimeout);
            executionTimeout = null;
        }
    } catch (error) {
        logger.error("Error managing execution state:", error);
        throw new AppError("Failed to manage execution state", 500, ERROR_TYPES.INTERNAL);
    }
};

// Stop execution route with enhanced error handling
router.post("/stop-execution", async (req, res, next) => {
    try {
        // Clear any existing timeout
        if (executionTimeout) {
            clearTimeout(executionTimeout);
            executionTimeout = null;
        }

        if (isExecuting) {
            isExecuting = false;
            logger.info("Execution stopped successfully");
            res.status(200).json({ 
                message: "Execution stopped successfully",
                status: "stopped"
            });
        } else {
            logger.info("No execution running");
            res.status(200).json({ 
                message: "No execution running",
                status: "idle"
            });
        }
    } catch (error) {
        logger.error("Error stopping execution:", error);
        next(new AppError("Failed to stop execution", 500, ERROR_TYPES.INTERNAL));
    }
});

// Enhanced array extraction with better pattern matching
const extractArray = (codeSnippet) => {
    try {
        // Advanced patterns for different programming languages
        const arrayPatterns = [
            /(?:const|let|var)\s+\w+\s*=\s*\[([^\]]+)\]/g, // JavaScript arrays
            /(?:int|double|float|long)\s+\w+\s*=\s*\{([^}]+)\}/g, // C, C++, Java arrays
            /vector<\w+>\s+\w+\s*=\s*\{([^}]+)\}/g, // C++ vectors
            /(?:\w+\s*=\s*)?\[([^\]]+)\]/g, // Python lists
            /(?:Array|List)<\w+>\s+\w+\s*=\s*\{([^}]+)\}/g, // C#, Java
            /\w+\s*=\s*new\s+(?:int|double|float|long)\[\]\s*{([^}]+)}/g, // Java, C# new array syntax
            /(?:Dim|Static)\s+\w+\s*\(\)\s+As\s+\w+\s*=\s*\{([^}]+)\}/g, // VB.NET
            /data\s+\w+\s*=\s*\[([^\]]+)\]/g, // Ruby arrays
            /\$\w+\s*=\s*\[([^\]]+)\]/g, // PHP arrays
            /int\s+\w+\[\]\s*=\s*\{([^}]+)\}/g, // C-style array declarations
        ];

        let extractedArrays = new Set(); // Use a Set to prevent duplicate arrays
        
        for (const pattern of arrayPatterns) {
            const matches = [...codeSnippet.matchAll(pattern)];
            for (const match of matches) {
                let numbers = match[1]
                    .split(/[,\s]+/)
                    .map(num => num.trim())
                    .filter(num => /^-?\d+(\.\d+)?$/.test(num)) // Ensure valid numbers
                    .map(Number);

                // Ignore incorrectly extracted single-element arrays
                if (numbers.length > 1 || (numbers.length === 1 && match[0].includes('{'))) {
                    extractedArrays.add(JSON.stringify(numbers));
                }
            }
        }

        return [...extractedArrays].map(arr => JSON.parse(arr));
    } catch (error) {
        logger.error("Error extracting arrays:", error);
        throw new AppError("Failed to extract arrays from code", 400, ERROR_TYPES.VALIDATION);
    }
};

// Enhanced code generation route
router.post("/generate", minuteLimiter, hourLimiter, async (req, res, next) => {
    try {
        const { problem } = req.body;

        // Input validation
        if (!problem) {
            throw new AppError("Problem statement is required", 400, ERROR_TYPES.VALIDATION);
        }

        if (problem.length > CONFIG.MAX_CODE_LENGTH) {
            throw new AppError(`Problem statement exceeds maximum length of ${CONFIG.MAX_CODE_LENGTH} characters`, 400, ERROR_TYPES.VALIDATION);
        }

        // API key validation
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) {
            throw new AppError("API key is missing", 500, ERROR_TYPES.CONFIGURATION);
        }

        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

        // Enhanced prompt construction
        const prompt = `
            ### Problem Statement:
            ${problem}

            ---

            ### Instructions:
            - If the problem is **related to loops** (e.g., \`for\`, \`while\` loops), format response as:
                - Loop condition
                - Update operation
                - Updated values per iteration
            - If the problem is **sorting-related**, provide:
                - Sorting type
                - Step-by-step breakdown (e.g., swaps, comparisons)
                - Example transformations like: divide(7654) → (76), (54), then merge(7,6) → 76, (5,4) → 54.
        `;

        // Enhanced API request with better error handling
        const response = await axios.post(endpoint, {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                maxOutputTokens: CONFIG.MAX_RESPONSE_TOKENS,
                temperature: CONFIG.TEMPERATURE,
                topK: CONFIG.TOP_K,
                topP: CONFIG.TOP_P
            }
        }, {
            headers: { "Content-Type": "application/json" },
            timeout: 30000 // 30 second timeout
        });

        const responseText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;

        if (!responseText) {
            throw new AppError("Received an empty response from Gemini API", 500, ERROR_TYPES.API);
        }

        const responseType = responseText.toLowerCase().includes("sort") ? "sorting" : "loop";

        // Enhanced response processing
        const processedResponse = {
            type: responseType,
            content: responseText.trim(),
            timestamp: Date.now()
        };

        res.json(processedResponse);

    } catch (error) {
        logger.error("Error in code generation:", error);
        next(error);
    }
});

// Enhanced JSON string sanitization
const sanitizeJsonString = (jsonString) => {
    try {
        return jsonString
            .replace(/"value":\s*undefined/g, '"value": null')
            .replace(/"args":\s*undefined/g, '"args": null')
            .replace(/"dpTable":\s*undefined/g, '"dpTable": null')
            .replace(/"otherState":\s*undefined/g, '"otherState": null')
            .replace(/"note":\s*undefined/g, '"note": null')
            .replace(/"description":\s*undefined/g, '"description": null')
            .replace(/"visited":\s*undefined/g, '"visited": []')
            .replace(/"recStack":\s*undefined/g, '"recStack": []')
            .replace(/"queue":\s*undefined/g, '"queue": []')
            .replace(/"adjacencyList":\s*undefined/g, '"adjacencyList": []')
            .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Remove control characters
            .replace(/\n/g, ' ') // Replace newlines with spaces
            .replace(/\s+/g, ' ') // Normalize whitespace
            .trim();
    } catch (error) {
        logger.error("Error sanitizing JSON string:", error);
        throw new AppError("Failed to sanitize JSON string", 500, ERROR_TYPES.PROCESSING);
    }
};

router.post("/debugger/sorting/mergesort", async (req, res) => {
    try {
        const userProblem = req.body.problem;
        
        // Extract all possible arrays
        const inputArrays = extractArray(userProblem);
        console.log("Extracted Arrays:", inputArrays); // Debugging output

        // Ensure at least one valid numeric array exists and extract the first valid one
        const validArray = inputArrays.find(
          arr =>
            Array.isArray(arr) &&
            arr.length > 0 &&
            arr.every(num => typeof num === "number" && !isNaN(num))
        );

        if (!validArray) {
            console.error("❌ No valid numeric array found in input.");
            return res.status(400).json({ error: "Invalid input: No numeric array found in the code." });
        }

        console.log("Using Numeric Array:", validArray); // Debugging output

        // API Key Validation
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) {
            console.error("❌ API key is missing.");
            return res.status(500).json({ error: "API key is missing. Check your .env file." });
        }

        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

        // Construct the API Prompt
        const prompt = `
    You are a Merge Sort visualization assistant. Your task is to break down the Merge Sort process step by step into a directed adjacency list representation. In this representation, each node corresponds to a state of the array (or subarray) at a particular step, and edges represent the transition from a parent node to its child nodes during both the divide and merge phases.

    ### Instructions:
    1. *Divide Phase*:
       - Show the recursive breakdown of the original array into smaller subarrays.
       - Each node should represent a subarray from the initial array down to single elements.
       - Represent the breakdown as a directed adjacency list where each node has edges to its children nodes.
    
    2. *Merge Phase*:
       - Show how the single elements are merged back together into sorted subarrays.
       - Include nodes for each merged state and add edges that represent the merging process.
    
    3. *Output Format*:  
       - Return a JSON object with three fields:
           - "inputArray": The original unsorted array.
           - "sortedArray": The final sorted array.
           - "mergeSortTable": A directed adjacency list representing the merge sort process.
       - The "mergeSortTable" should be an object where each key is a unique identifier for a step. Each key's value must be an object containing:
           - "state": The array (or subarray) state at that step.
           - "children": An array of keys representing the next steps (child nodes).
       - Example:
        \`\`\`json
      
 {
  "inputArray": [2, 1, 3, 45],
  "sortedArray": [1, 2, 3, 45],
  "mergeSortTable": {
    "nodes": [
      { "id": "step1", "state": [2, 1, 3, 45] },
      { "id": "step2", "state": [2, 1] },
      { "id": "step3", "state": [3, 45] },
      { "id": "step4", "state": [2] },
      { "id": "step5", "state": [1] },
      { "id": "step6", "state": [3] },
      { "id": "step7", "state": [45] },
      { "id": "step8", "state": [1, 2] },
      { "id": "step9", "state": [3, 45] },
      { "id": "step10", "state": [1, 2, 3, 45] }
    ],
    "edges": [
      { "source": "step1", "target": "step2" },
      { "source": "step1", "target": "step3" },
      { "source": "step2", "target": "step4" },
      { "source": "step2", "target": "step5" },
      { "source": "step3", "target": "step6" },
      { "source": "step3", "target": "step7" },
      { "source": "step4", "target": "step8" },
      { "source": "step5", "target": "step8" },
      { "source": "step6", "target": "step9" },
      { "source": "step7", "target": "step9" },
      { "source": "step8", "target": "step10" },
      { "source": "step9", "target": "step10" }
    ]
  },
  "executionTrace": [
    {
      "function": "mergeSort",
      "action": "Calculate mid index for full array",
      "lineNumber": 34,
      "code": "int mid = left + (right - left) / 2;"
    },
    {
      "function": "mergeSort",
      "action": "Divide full array into left and right halves",
      "lineNumber": 34,
      "code": "Left half: [2, 1] | Right half: [3, 45]"
    },
    {
      "function": "mergeSort",
      "action": "Recurse on left half",
      "lineNumber": 35,
      "code": "mergeSort(arr, left, mid);  // Operating on [2, 1]"
    },
    {
      "function": "mergeSort",
      "action": "Calculate mid index for left half",
      "lineNumber": 34,
      "code": "int mid = left + ((mid - left) / 2);  // For subarray [2, 1]"
    },
    {
      "function": "mergeSort",
      "action": "Divide left half into individual elements",
      "lineNumber": 34,
      "code": "Left: [2] | Right: [1]"
    },
    {
      "function": "mergeSort",
      "action": "Recurse on left sub-half",
      "lineNumber": 35,
      "code": "mergeSort(arr, left, mid);  // Operating on [2]"
    },
    {
      "function": "mergeSort",
      "action": "Recurse on right sub-half",
      "lineNumber": 36,
      "code": "mergeSort(arr, mid + 1, right);  // Operating on [1]"
    },
    {
      "function": "merge",
      "action": "Merge left sub-halves into sorted subarray",
      "lineNumber": 12,
      "code": "vector<int> L(n1), R(n2);  // Merging [2] and [1] into [1, 2]"
    },
    {
      "function": "mergeSort",
      "action": "Recurse on right half",
      "lineNumber": 36,
      "code": "mergeSort(arr, mid + 1, right);  // Operating on [3, 45]"
    },
    {
      "function": "mergeSort",
      "action": "Calculate mid index for right half",
      "lineNumber": 34,
      "code": "int mid = left + (right - left) / 2;  // For subarray [3, 45]"
    },
    {
      "function": "mergeSort",
      "action": "Divide right half into individual elements",
      "lineNumber": 34,
      "code": "Left: [3] | Right: [45]"
    },
    {
      "function": "mergeSort",
      "action": "Recurse on left sub-half of right half",
      "lineNumber": 35,
      "code": "mergeSort(arr, left, mid);  // Operating on [3]"
    },
    {
      "function": "mergeSort",
      "action": "Recurse on right sub-half of right half",
      "lineNumber": 36,
      "code": "mergeSort(arr, mid + 1, right);  // Operating on [45]"
    },
    {
      "function": "merge",
      "action": "Merge right sub-halves into sorted subarray",
      "lineNumber": 12,
      "code": "vector<int> L(n1), R(n2);  // Merging [3] and [45] into [3, 45]"
    },
    {
      "function": "merge",
      "action": "Final merge of sorted left and right halves",
      "lineNumber": 12,
      "code": "vector<int> L(n1), R(n2);  // Merging [1, 2] and [3, 45] into [1, 2, 3, 45]"
    }
  ],
  "debugInfo": { "lineNumber": 60 }
}

        \`\`\`
       - **Strictly adhere** to this JSON format.
    
    Now, process the following input array and return the output strictly in this format:

    *Input Array:* ${JSON.stringify(validArray)}
`;

        // Send Request to Gemini API
        const response = await axios.post(
            endpoint,
            {
                contents: [{ parts: [{ text: prompt }] }]
            },
            {
                headers: { "Content-Type": "application/json" }
            }
        );

        // Extract and Validate Gemini API Response
        const responseText = response?.data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!responseText) {
            console.error("❌ Received an empty response from Gemini API.");
            return res.status(500).json({ error: "Received an empty response from Gemini API." });
        }

        let parsedResponse;
        try {
            // Remove any ```json or ``` from the response, then parse
            const cleanedJson = responseText.replace(/```json|```/g, "").trim();
            parsedResponse = JSON.parse(cleanedJson);

            // Validate the presence of required fields
            if (
              !Array.isArray(parsedResponse.inputArray) ||
              !Array.isArray(parsedResponse.sortedArray) ||
              !parsedResponse.mergeSortTable ||
              typeof parsedResponse.mergeSortTable !== "object"
            ) {
                throw new Error("Missing expected fields in API response.");
            }
        } catch (error) {
            console.error("❌ Error parsing JSON from Gemini API:", error.message);
            return res.status(500).json({ error: "Received an invalid JSON response from Gemini API." });
        }

        // Send Response to Frontend
        // This ensures your frontend receives the fields it needs:
        //   inputArray, sortedArray, and mergeSortTable
        res.json({
            inputArray: parsedResponse.inputArray,
            sortedArray: parsedResponse.sortedArray,
            mergeSortTable: parsedResponse.mergeSortTable,
            executionTrace:  parsedResponse.executionTrace
        });

    } catch (error) {
        console.error("❌ Error fetching from Gemini API:", error.response?.data || error.message);
        res.status(500).json({ error: "Failed to generate response from Gemini API." });
    }
});

router.post('/debugger/recursion/main', async (req, res) => {
  try {
    const { problem, language, input } = req.body;

    // Validate request body
    if (!problem || !language) {
      console.error("❌ Missing required fields in request body");
      return res.status(400).json({ 
        error: "Missing required fields", 
        details: "Both 'problem' and 'language' are required" 
      });
    }

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      console.error("❌ Gemini API key is missing in environment variables");
      return res.status(500).json({ error: "API key is missing. Check your .env file." });
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    const prompt = `
You are a code execution analyzer. Your task is to analyze the recursive function and generate a complete trace.

Given this recursive function in ${language}:

${problem}

And it is called with:

${input || "no input provided"}

Generate a JSON-formatted trace of the function calls and returns. Each trace step should follow this structure:
[
  { "event": "call", "func": "function_name", "args": { "param1": value }, "depth": number },
  { "event": "return", "func": "function_name", "value": returnValue, "depth": number, "note": "base case" }
]

Important:
1. Only output valid JSON
2. Ensure all JSON objects are properly closed
3. Include the "note" field only for base case returns
4. Keep the response concise and complete
5. Do not include any explanations or markdown
6. Limit the trace to a maximum of 20 steps
7. For large inputs, focus on the first few recursive calls

Example output format:
[
  {"event":"call","func":"fibonacci","args":{"n":3},"depth":0},
  {"event":"call","func":"fibonacci","args":{"n":2},"depth":1},
  {"event":"call","func":"fibonacci","args":{"n":1},"depth":2},
  {"event":"return","func":"fibonacci","value":1,"depth":2,"note":"base case"},
  {"event":"call","func":"fibonacci","args":{"n":0},"depth":2},
  {"event":"return","func":"fibonacci","value":0,"depth":2,"note":"base case"},
  {"event":"return","func":"fibonacci","value":1,"depth":1},
  {"event":"call","func":"fibonacci","args":{"n":1},"depth":1},
  {"event":"return","func":"fibonacci","value":1,"depth":1,"note":"base case"},
  {"event":"return","func":"fibonacci","value":2,"depth":0}
]`;

    console.log("📝 Sending request to Gemini API");

    const response = await axios.post(
      endpoint,
      { 
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          maxOutputTokens: 2048,
          temperature: 0.1,
          topP: 0.8,
          topK: 40
        }
      },
      { headers: { "Content-Type": "application/json" } }
    );

    const responseText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!responseText) {
      console.error("❌ Empty response from Gemini API");
      return res.status(500).json({ error: "Received an empty response from Gemini API." });
    }

    // Clean the response and ensure it's valid JSON
    const cleanedResponseText = responseText
      .replace(/```(json)?/g, '') // Remove markdown code blocks
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Remove control characters
      .replace(/\n/g, ' ') // Replace newlines with spaces
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim();

    let parsedOutput;
    try {
      // Sanitize the response before parsing
      const sanitizedJson = sanitizeJsonString(cleanedResponseText);
      parsedOutput = JSON.parse(sanitizedJson);
      
      // Validate the structure of the parsed output
      if (!Array.isArray(parsedOutput)) {
        throw new Error("Response is not an array");
      }
      
      // Limit the number of steps to prevent overwhelming the frontend
      if (parsedOutput.length > 20) {
        parsedOutput = parsedOutput.slice(0, 20);
      }
      
      // Validate each step in the trace
      parsedOutput.forEach((step, index) => {
        if (!step.event || !step.func || typeof step.depth !== 'number') {
          throw new Error(`Invalid step at index ${index}`);
        }
      });

      console.log("✅ Successfully parsed and validated JSON response");
      res.json(parsedOutput);
    } catch (parseError) {
      console.error("❌ JSON parsing error:", parseError);
      console.error("Raw response:", cleanedResponseText);
      
      // Try to fix common JSON issues
      try {
        // If the JSON is cut off, try to complete it
        const fixedJson = cleanedResponseText.replace(/,\s*$/, '') + ']';
        const sanitizedFixedJson = sanitizeJsonString(fixedJson);
        parsedOutput = JSON.parse(sanitizedFixedJson);
        console.log("✅ Successfully parsed fixed JSON response");
        res.json(parsedOutput);
      } catch (fixError) {
        return res.status(500).json({ 
          error: "Failed to parse the response as JSON",
          details: parseError.message,
          raw: cleanedResponseText
        });
      }
    }

  } catch (error) {
    console.error("❌ Error in /debugger/recursion/main:", error);
    res.status(500).json({ 
      error: "Failed to generate response from Gemini API",
      details: error.message
    });
  }
});


router.post('/debugger/dynamicprogramming/main', async (req, res) => { 
  try {
    const { problem, language, input } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(500).json({ error: "API key is missing. Check your .env file." });
    }

    // Construct the Gemini API endpoint using the API key from the .env file
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    // Prepare the new prompt with the desired JSON output format for dynamic programming.
    // It includes dpTable field to capture memoisation/tabulation/space optimisation info.
    const prompt = `
You are a dynamic programming execution analyzer.

Given this dynamic programming problem in ${language}:

${problem}

And it is called with:

${input}

Generate a JSON-formatted trace of the execution, including DP table states.
Each trace step should follow this structure:
[
  {
    "event": "call",
    "func": "function_name",
    "args": { "param1": value },
    "depth": number,
    "dpTable": { /* current state of dp table / memoisation cache */ }
  },
  {
    "event": "return",
    "func": "function_name",
    "value": returnValue,
    "depth": number,
    "note": "base case reached", // Include note only when applicable
    "dpTable": { /* current state of dp table / memoisation cache */ }
  }
]

Only output the JSON. Do not explain.
`;

    // Call the Gemini API
    const response = await axios.post(
      endpoint,
      { contents: [{ parts: [{ text: prompt }] }] },
      { headers: { "Content-Type": "application/json" } }
    );

    // Extract the response text from the Gemini API
    const responseText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!responseText) {
      return res.status(500).json({ error: "Received an empty response from Gemini API." });
    }

    // Clean the response by removing markdown code fences and an optional "json" tag
    const cleanedResponseText = responseText.replace(/```(json)?/g, '').trim();

    // Try to parse the cleaned JSON response
    let parsedOutput;
    try {
      const sanitizedJson = sanitizeJsonString(cleanedResponseText);
      parsedOutput = JSON.parse(sanitizedJson);
    } catch (parseError) {
      return res.status(500).json({ error: "Failed to parse the response as JSON.", raw: responseText });
    }

    // Send the parsed JSON output back to the frontend
    res.json(parsedOutput);

  } catch (error) {
    console.error("Error fetching from Gemini API:", error.response?.data || error.message);
    res.status(500).json({ error: "Failed to generate response from Gemini API." });
  }
});


//  Linked List

router.post('/debugger/LinkedList/main', async (req, res) => {
  try {
    let { codeInput } = req.body;

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(500).json({ error: 'API key is missing. Check your .env file.' });
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    const prompt = `
You are a debugger for Linked List data structures.
Given the input code below, produce a JSON trace of its step-by-step execution.

Each step in the trace should be an object with this structure:

[
  {
    "event": "call",
    "description": "A very small and concise one-line explanation of the step.",
    "func": "function_name",
    "args": { "param1": value },
    "depth": number,
    "visited": ["", "V", "", "V", …],   // an array of length N where "V" marks visited nodes
    "recStack": [],
    "queue": [],
    "list": ["1", "2", "3", ...],       // represents the current linked list structure
    "pointer": "2",                     // the node value where the current pointer (e.g. 'current') is
    "otherState": { /* any other specific state, optional */ }
  },
  {
    "event": "return",
    "func": "function_name",
    "description": "One line summary of what just returned.",
    "value": returnValue,
    "depth": number,
    "note": "if base case or end of list reached",
    "visited": [],
    "recStack": [],
    "queue": [],
    "list": ["1", "2", "3"],
    "pointer": null,
    "otherState": {}
  }
]

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


// routes/trees.js

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

// routes/graphDebugger.js

router.post('/debugger/graphs/main', async (req, res) => {
  try {
    let { codeInput } = req.body;

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(500).json({ error: 'API key is missing. Check your .env file.' });
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

   const prompt = `
You are a debugger for graph algorithms (DFS, BFS, and others).
Given the input code below, produce a JSON trace of its step-by-step execution.

Each step in the trace should be an object with this structure:

[
  {
    "event": "call",
    "description": "a very small and concise one line of the change in the current steps taking place",
    "func": "function_name",
    "args": { "param1": value },
    "depth": number,
    "visited": ["", "V", "", "V", …],      // an array of length N: put "V" at each visited index, "" otherwise
    "recStack": [/* nodes in recursion stack, or [] */],
     "queue": [/* node val in queue, or [] remeber it should give the only the current state of queue and values and not the previous  */],
    "adjacencyList": [ [B, C], [A, C], [] ],
    "otherState": { /* any other algorithm-specific state, optional */ }
  },
  {
    "event": "return",
    "func": "function_name",
    "description": "a very small and concise one line of the change in the current steps taking place",
    "value": returnValue,
    "depth": number,
    "note": "base case reached",  // optional
    "visited": [/* nodes visited so far */],
    "recStack": [/* nodes in recursion stack, or [] */],
    "queue": [/* nodes in queue, or [] remeber it should give the only the current state of queue and values and not the previous  */],
   "adjacencyList": [ [B, C], [A, C], [] ],
    "otherState": { /* any other algorithm-specific state, optional */ }
  }
]

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

    const cleaned = rawText
  .replace(/```(?:json)?/g, '')
  .replace(/```/g, '')
  .replace(/[“”]/g, '"')
  .replace(/[‘’]/g, "'")
  .replace(/,\s*([\]}])/g, '$1')  // remove trailing commas
  .trim();

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


router.post('/debugger/sorting/bubblesort', async (req, res) => {
  try {
    const { problem /* your bubbleSort code */, language, input } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: "Missing API key." });
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    // Build the prompt: wrap the user's bubbleSort in a debugger harness
    const prompt = `
You are a code execution analyzer.

Wrap this JavaScript bubbleSort function in a debugger harness that:
  1. Emits a "call" event when bubbleSort is invoked.
  2. Emits a "compare" event before each comparison, including the current array.
  3. Emits a "swap" event whenever two elements are swapped, including the new array.
  4. Emits a "return" event when sorting completes, including the final sorted array.
  5. Uses the following JSON event structure:

    { "event": "compare",  "array": { "i": <i>, "j": <j> },    "depth": 0, "array": [...] },
    { "event": "swap",     "array": { "i": <i>, "j": <j> },    "depth": 0, "array": [...] },

Only output the complete JSON array of events—no prose, no markdown.

Here's the original function:

${problem}

And here's how it's called:

const arr = ${input};
bubbleSort(arr);
`;

    // Call Gemini
    const response = await axios.post(
      endpoint,
      { contents: [{ parts: [{ text: prompt }] }] },
      { headers: { "Content-Type": "application/json" } }
    );

    const raw = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const cleaned = raw.replace(/```(?:json)?/g, '').trim();

    let trace;
    try {
      const sanitizedJson = sanitizeJsonString(cleaned);
      trace = JSON.parse(sanitizedJson);
    } catch (e) {
      return res.status(500).json({ error: "Failed to parse JSON.", raw });
    }

    // Send the trace back
    res.json({ trace });

  } catch (error) {
    console.error(error.response?.data || error);
    res.status(500).json({ error: "Debug trace generation failed." });
  }
});



// AI-Generated Problem Classification Route
router.post("/debugger/identifyproblem", async (req, res) => {
    try {
        const userProblem = req.body.problem;
        const apiKey = process.env.GEMINI_API_KEY;

        if (!apiKey) {
            return res.status(500).json({ error: "API key is missing. Check your .env file." });
        }

        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

        // Prompt for problem classification
        const prompt = `
            You are a problem-classification assistant. Your task is to analyze the following code and identify:
            
            1. **Problem Type**:
                - Classify the problem into broad categories like: 
                  - Sorting
                  - Searching
                  - Dynamic Programming
                  - Recursion
                  - Trees
                  - Graphs
                  - LinkedList
                  - Others
            if it is of dynamic programming return dynamic programmimng only even if it is DP with memoisation dont retun recursion
            2. **Specific Problem Type**:
                - If it's a **Sorting** problem, identify the exact sorting algorithm used (e.g., Merge Sort, Quick Sort, Bubble Sort, etc.).
                - If it's a **Searching** problem, identify the exact search algorithm used (e.g., Binary Search, Linear Search, etc.).
                - For any other category, simply return "main".

            Your task is to return the result in the format below:

            <General Category>  
            <Exact Algorithm or Technique>
            
            You must follow the format STRICTLY with no extra characters, including no backticks or code blocks.
            
            Here's the code to classify:

            ${userProblem}
        `;

        // API request to the Gemini service
        const response = await axios.post(endpoint, {
            contents: [{ parts: [{ text: prompt }] }]
        }, {
            headers: { "Content-Type": "application/json" }
        });

        const responseText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!responseText) {
            return res.status(500).json({ error: "Received an empty response from Gemini API." });
        }

        // Clean up the response and extract relevant information
        const cleanResponse = responseText.trim().split('\n').map(line => line.trim());
        const problemType = cleanResponse[0]?.replace("Problem Type:", "").trim();
        const specificType = cleanResponse[1]?.replace("Specific Problem Type:", "").trim();

        // If either part is missing, handle gracefully
        if (!problemType || !specificType) {
            return res.status(400).json({ error: "Invalid response format. Ensure correct classification." });
        }

        // Convert problemType and specificType to lowercase and remove spaces
        const formattedProblemType = problemType.toLowerCase().replace(/\s+/g, '');
        const formattedSpecificType = specificType.toLowerCase().replace(/\s+/g, '');

        res.json({
            problemType: formattedProblemType,  // Adjusted this field
            specificType: formattedSpecificType  // Adjusted this field
        });

    } catch (error) {
        console.error("Error fetching from Gemini API:", error.response?.data || error.message);
        res.status(500).json({ error: "Failed to generate response from Gemini API." });
    }
});

module.exports = {
    router,
    setExecutionState,
    CONFIG
};