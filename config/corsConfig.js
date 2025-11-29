const cors = require("cors");
const { AppError, ERROR_TYPES } = require('../middleware/errorHandler');
const logger = require("./logger");
const rateLimit = require('express-rate-limit');

// Enhanced configuration
const CONFIG = {
    MAX_REQUESTS_PER_MINUTE: 100,
    MAX_REQUESTS_PER_HOUR: 1000,
    CORS_CACHE_DURATION: 86400, // 24 hours
    ALLOWED_METHODS: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    ALLOWED_HEADERS: [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
        "X-CSRF-Token",
        "X-API-Key",
        "X-Client-Version",
        "X-Client-Platform"
    ],
    EXPOSED_HEADERS: [
        "Set-Cookie",
        "X-Rate-Limit-Limit",
        "X-Rate-Limit-Remaining",
        "X-Rate-Limit-Reset"
    ],
    ENVIRONMENT: process.env.NODE_ENV || 'development'
};

// Define allowed origins with environment-specific settings
const allowedOrigins = new Set([
    // Development
    "http://localhost:5000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:5176",
    "http://127.0.0.1:5000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:5175",
    "http://127.0.0.1:5176",
    "http://localhost:3000",
    "http://127.0.0.1:3000",

    // Production
    "https://code-stream-96syog8wp-anurag-amrev-7557s-projects.vercel.app",
    "https://code-stream-eta.vercel.app",
    "https://codeanimation-mauve.vercel.app",

    ...(CONFIG.ENVIRONMENT === 'production' ? [] : [])
]);

// Rate limiters for CORS requests
const corsRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: CONFIG.MAX_REQUESTS_PER_MINUTE,
    message: { error: 'Too many requests from this origin' },
    handler: (req, res, next) => {
        next(new AppError('CORS rate limit exceeded', 429, ERROR_TYPES.RATE_LIMIT));
    },
    keyGenerator: (req) => req.headers.origin || req.ip,
    skip: (req) => !req.headers.origin
});

// Enhanced CORS Configuration
const corsOptions = {
    origin: (origin, callback) => {
        try {
            if (!origin) {
                logger.info('Request with no origin (non-browser request)');
                return callback(null, true);
            }

            if (allowedOrigins.has(origin)) {
                logger.info(`Allowed CORS request from: ${origin}`);
                return callback(null, true);
            }

            logger.warning(`Blocked CORS request from unauthorized origin: ${origin}`);
            callback(new AppError('CORS policy violation', 403, ERROR_TYPES.SECURITY), false);
        } catch (error) {
            logger.error('Error in CORS origin check:', error);
            callback(new AppError('CORS configuration error', 500, ERROR_TYPES.INTERNAL), false);
        }
    },
    credentials: true,
    methods: CONFIG.ALLOWED_METHODS,
    allowedHeaders: [...CONFIG.ALLOWED_HEADERS, 'Authorization'],
    exposedHeaders: CONFIG.EXPOSED_HEADERS,
    optionsSuccessStatus: 204,
    preflightContinue: false,
    maxAge: CONFIG.CORS_CACHE_DURATION,
    secure: CONFIG.ENVIRONMENT === 'production',
    sameSite: CONFIG.ENVIRONMENT === 'production' ? 'strict' : 'lax'
};

// Enhanced middleware to log and validate CORS requests
const logCorsRequests = (req, res, next) => {
    try {
        const origin = req.headers.origin || 'Unknown';
        const method = req.method;
        const path = req.path;
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const ip = req.ip || req.connection.remoteAddress;

        logger.info('CORS Request Details:', {
            origin,
            method,
            path,
            userAgent,
            ip,
            timestamp: new Date().toISOString()
        });

        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

        res.setHeader('X-Rate-Limit-Limit', CONFIG.MAX_REQUESTS_PER_MINUTE);
        res.setHeader('X-Rate-Limit-Remaining', res.getHeader('X-Rate-Limit-Remaining') || CONFIG.MAX_REQUESTS_PER_MINUTE);
        res.setHeader('X-Rate-Limit-Reset', Math.floor(Date.now() / 1000) + 60);

        next();
    } catch (error) {
        logger.error('Error in CORS request logging:', error);
        next(new AppError('CORS request logging error', 500, ERROR_TYPES.INTERNAL));
    }
};

// Middleware to handle CORS errors
const handleCorsErrors = (err, req, res, next) => {
    if (err.name === 'CORSError') {
        logger.error('CORS Error:', {
            error: err.message,
            origin: req.headers.origin,
            method: req.method,
            path: req.path
        });

        return res.status(403).json({
            error: 'CORS policy violation',
            message: 'Access denied due to CORS policy',
            details: err.message
        });
    }
    next(err);
};

module.exports = {
    corsOptions,
    logCorsRequests,
    handleCorsErrors,
    corsRateLimiter,
    CONFIG
};
