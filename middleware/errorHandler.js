const logger = require('../config/logger');

// Custom error classes for better error handling
class AppError extends Error {
    constructor(message, statusCode, errorCode) {
        super(message);
        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;

        Error.captureStackTrace(this, this.constructor);
    }
}

// Error type mappings for consistent error responses
const ERROR_TYPES = {
    VALIDATION: 'VALIDATION_ERROR',
    AUTHENTICATION: 'AUTHENTICATION_ERROR',
    AUTHORIZATION: 'AUTHORIZATION_ERROR',
    NOT_FOUND: 'NOT_FOUND_ERROR',
    CONFLICT: 'CONFLICT_ERROR',
    RATE_LIMIT: 'RATE_LIMIT_ERROR',
    DATABASE: 'DATABASE_ERROR',
    EXTERNAL: 'EXTERNAL_SERVICE_ERROR',
    INTERNAL: 'INTERNAL_SERVER_ERROR'
};

const errorHandler = (err, req, res, next) => {
    // Log the error with request context
    logger.error('Error occurred:', {
        message: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
        ip: req.ip,
        userId: req.user ? req.user.id : 'anonymous',
        timestamp: new Date().toISOString(),
        errorType: err.name,
        errorCode: err.code,
        statusCode: err.statusCode || err.status || 500
    });

    // Handle MongoDB duplicate key errors
    if (err.code === 11000) {
        const field = Object.keys(err.keyPattern)[0];
        return res.status(409).json({
            status: 'fail',
            error: ERROR_TYPES.CONFLICT,
            message: `An account with this ${field} already exists`,
            suggestion: field === 'email' ? 'Please try logging in instead or use a different email address' : 'Please use a different value',
            field: field
        });
    }

    // Handle MongoDB validation errors
    if (err.name === 'ValidationError') {
        const errors = Object.values(err.errors).map(e => ({
            field: e.path,
            message: e.message
        }));
        
        return res.status(400).json({
            status: 'fail',
            error: ERROR_TYPES.VALIDATION,
            message: 'Validation Error',
            details: errors
        });
    }

    // Handle JWT errors
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            status: 'fail',
            error: ERROR_TYPES.AUTHENTICATION,
            message: 'Invalid token',
            suggestion: 'Please log in again'
        });
    }

    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
            status: 'fail',
            error: ERROR_TYPES.AUTHENTICATION,
            message: 'Token expired',
            suggestion: 'Please log in again'
        });
    }

    // Handle rate limiting errors
    if (err.type === 'RateLimitExceeded') {
        return res.status(429).json({
            status: 'fail',
            error: ERROR_TYPES.RATE_LIMIT,
            message: 'Too many requests',
            suggestion: 'Please try again later',
            retryAfter: err.retryAfter
        });
    }

    // Handle database connection errors
    if (err.name === 'MongoServerError' || err.name === 'MongooseError') {
        return res.status(503).json({
            status: 'error',
            error: ERROR_TYPES.DATABASE,
            message: 'Database connection error',
            suggestion: 'Please try again later'
        });
    }

    // Handle external service errors
    if (err.isAxiosError) {
        return res.status(502).json({
            status: 'error',
            error: ERROR_TYPES.EXTERNAL,
            message: 'External service error',
            suggestion: 'Please try again later'
        });
    }

    // Handle custom AppError
    if (err instanceof AppError) {
        return res.status(err.statusCode).json({
            status: err.status,
            error: err.errorCode,
            message: err.message,
            ...(err.suggestion && { suggestion: err.suggestion })
        });
    }

    // Handle 404 errors
    if (err.status === 404) {
        return res.status(404).json({
            status: 'fail',
            error: ERROR_TYPES.NOT_FOUND,
            message: 'Resource not found',
            suggestion: 'Please check the URL and try again'
        });
    }

    // Default error response
    const statusCode = err.status || 500;
    const response = {
        status: statusCode === 500 ? 'error' : 'fail',
        error: ERROR_TYPES.INTERNAL,
        message: err.message || 'An unexpected error occurred'
    };

    // Add stack trace in development
    if (process.env.NODE_ENV === 'development') {
        response.stack = err.stack;
        response.details = err;
    }

    res.status(statusCode).json(response);
};

module.exports = {
    errorHandler,
    AppError,
    ERROR_TYPES
}; 