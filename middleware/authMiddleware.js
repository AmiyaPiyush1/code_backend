const jwt = require("jsonwebtoken");
const logger = require("../config/logger");
const User = require('../models/User');
const { AppError, ERROR_TYPES } = require('./errorHandler');
require("dotenv").config();

// Security configuration
const AUTH_CONFIG = {
    TOKEN_EXPIRY: '24h',
    REFRESH_TOKEN_EXPIRY: '7d',
    RATE_LIMIT: {
        WINDOW_MS: 15 * 60 * 1000, // 15 minutes
        MAX_ATTEMPTS: 5
    },
    TOKEN_VERSION: 1, // Increment this to invalidate all tokens
    SECURITY_HEADERS: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
    }
};

// Rate limiting store
const rateLimitStore = new Map();

// Clean up expired rate limit entries
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of rateLimitStore.entries()) {
        if (now - value.timestamp > AUTH_CONFIG.RATE_LIMIT.WINDOW_MS) {
            rateLimitStore.delete(key);
        }
    }
}, 60000); // Clean up every minute

// Rate limiting middleware
const rateLimiter = (req, res, next) => {
    const key = `${req.ip}-${req.path}`;
    const now = Date.now();
    const windowStart = now - AUTH_CONFIG.RATE_LIMIT.WINDOW_MS;

    const requestLog = rateLimitStore.get(key) || { count: 0, timestamp: now };
    
    // Reset count if window has passed
    if (requestLog.timestamp < windowStart) {
        requestLog.count = 0;
        requestLog.timestamp = now;
    }

    // Check if rate limit exceeded
    if (requestLog.count >= AUTH_CONFIG.RATE_LIMIT.MAX_ATTEMPTS) {
        logger.warning(`Rate limit exceeded for IP: ${req.ip}`);
        throw new AppError('Too many requests', 429, ERROR_TYPES.RATE_LIMIT);
    }

    // Update rate limit store
    requestLog.count++;
    rateLimitStore.set(key, requestLog);

    // Add rate limit headers
    res.setHeader('X-RateLimit-Limit', AUTH_CONFIG.RATE_LIMIT.MAX_ATTEMPTS);
    res.setHeader('X-RateLimit-Remaining', AUTH_CONFIG.RATE_LIMIT.MAX_ATTEMPTS - requestLog.count);
    res.setHeader('X-RateLimit-Reset', Math.ceil((requestLog.timestamp + AUTH_CONFIG.RATE_LIMIT.WINDOW_MS) / 1000));

    next();
};

// Token verification with enhanced security
const verifyToken = async (token) => {
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Verify user still exists and is active
        const user = await User.findById(decoded.id);
        if (!user) {
            throw new AppError('User not found', 401, ERROR_TYPES.AUTHENTICATION);
        }

        return { decoded, user };
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            throw new AppError('Invalid token', 401, ERROR_TYPES.AUTHENTICATION);
        }
        if (error.name === 'TokenExpiredError') {
            throw new AppError('Token expired', 401, ERROR_TYPES.AUTHENTICATION);
        }
        throw error;
    }
};

// Authentication Middleware with enhanced security
const authenticateUser = async (req, res, next) => {
    try {
        // Apply security headers
        Object.entries(AUTH_CONFIG.SECURITY_HEADERS).forEach(([key, value]) => {
            res.setHeader(key, value);
        });

        // First check Authorization header
        let token = null;
        if (req.headers.authorization) {
            const authHeader = req.headers.authorization;
            if (authHeader.startsWith('Bearer ')) {
                token = authHeader.substring(7);
            }
        }
        
        // If not in Authorization header, check cookies
        if (!token) {
            token = req.cookies.token;
        }

        if (!token) {
            logger.warning(`Unauthorized access attempt from IP: ${req.ip}`);
            throw new AppError('Access denied. No token provided', 401, ERROR_TYPES.AUTHENTICATION);
        }

        const { decoded, user } = await verifyToken(token);
        
        // Attach user info to request object
        req.user = {
            id: user._id,
            email: user.email,
            name: user.name,
            picture: user.picture,
            isAdmin: user.isAdmin,
            permissions: user.permissions
        };

        // Log successful authentication
        logger.info(`User authenticated: ${user.email} (${req.ip})`);

        next();
    } catch (error) {
        next(error);
    }
};

// Role-based access control middleware
const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            throw new AppError('Authentication required', 401, ERROR_TYPES.AUTHENTICATION);
        }

        if (!roles.includes(req.user.role)) {
            logger.warning(`Unauthorized role access attempt: ${req.user.email} (${req.ip})`);
            throw new AppError('Insufficient permissions', 403, ERROR_TYPES.AUTHORIZATION);
        }

        next();
    };
};

// Export middleware as Express middleware functions
module.exports = {
    authenticateUser: (req, res, next) => authenticateUser(req, res, next),
    requireRole: (roles) => requireRole(roles),
    rateLimiter: (req, res, next) => rateLimiter(req, res, next),
    AUTH_CONFIG
};