const winston = require('winston');
const path = require('path');
const fs = require('fs');
const DailyRotateFile = require('winston-daily-rotate-file');
const { chalk } = require('chalk');

// Ensure logs directory exists
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log levels with custom priorities and colors
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
  verbose: 5,
  silly: 6,
};

// Enhanced color scheme with better contrast
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
  verbose: 'cyan',
  silly: 'gray',
  timestamp: 'gray',
  context: 'cyan',
  errorStack: 'red',
  requestId: 'yellow',
  performance: 'green',
  security: 'red',
};

// Add colors to winston
winston.addColors(colors);

// Custom format for error objects
const errorFormat = winston.format((info) => {
  if (info.error instanceof Error) {
    info.error = {
      message: info.error.message,
      stack: info.error.stack,
      ...info.error,
    };
  }
  return info;
});

// Custom format for request IDs
const requestIdFormat = winston.format((info) => {
  if (info.context?.requestId) {
    info.requestId = info.context.requestId;
  }
  return info;
});

// Custom format for performance metrics
const performanceFormat = winston.format((info) => {
  if (info.context?.type === 'performance') {
    info.performance = {
      duration: info.context.duration,
      ...info.context,
    };
  }
  return info;
});

// Define log format with enhanced visual hierarchy
const format = winston.format.combine(
  errorFormat(),
  requestIdFormat(),
  performanceFormat(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ all: true }),
  winston.format.printf((info) => {
    const { timestamp, level, message, context, error, requestId, performance } = info;
    
    // Format timestamp
    const timestampStr = `[${timestamp}]`;
    
    // Format level with custom styling
    const levelStr = (() => {
      const levelColors = {
        error: 'red',
        warn: 'yellow',
        info: 'green',
        http: 'magenta',
        debug: 'blue',
        verbose: 'cyan',
        silly: 'gray',
      };
      return level.toUpperCase();
    })();
    
    // Format request ID if present
    const requestIdStr = requestId ? `[${requestId}]` : '';
    
    // Format context with better structure
    const contextStr = context ? (() => {
      const contextObj = { ...context };
      delete contextObj.requestId; // Remove requestId as it's handled separately
      return `\nContext: ${JSON.stringify(contextObj, null, 2)}`;
    })() : '';
    
    // Format error with better structure
    const errorStr = error ? (() => {
      const errorMessage = `\nError: ${error.message}`;
      const errorStack = error.stack ? `\nStack:\n${error.stack}` : '';
      return `${errorMessage}${errorStack}`;
    })() : '';
    
    // Format performance metrics
    const performanceStr = performance ? (() => {
      const duration = `${performance.duration}ms`;
      return `\nPerformance: ${duration}`;
    })() : '';
    
    // Format security information
    const securityStr = context?.type === 'security' ? (() => {
      return `\nSecurity Event: ${JSON.stringify(context, null, 2)}`;
    })() : '';
    
    // Combine all parts with proper spacing
    return [
      `${timestampStr} ${levelStr}${requestIdStr}`,
      message,
      contextStr,
      errorStr,
      performanceStr,
      securityStr,
    ].filter(Boolean).join('\n');
  }),
);

// Define file transport options with enhanced formatting
const fileTransportOptions = {
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '20m',
  maxFiles: '14d',
  format: winston.format.combine(
    winston.format.uncolorize(),
    winston.format.timestamp(),
    winston.format.json()
  ),
};

// Define transports
const transports = [
  // Console transport with enhanced formatting
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize({ all: true }),
      format
    ),
  }),
  
  // Rotating file transport for error logs
  new DailyRotateFile({
    ...fileTransportOptions,
    filename: path.join(logsDir, 'error-%DATE%.log'),
    level: 'error',
  }),
  
  // Rotating file transport for all logs
  new DailyRotateFile({
    ...fileTransportOptions,
    filename: path.join(logsDir, 'combined-%DATE%.log'),
  }),
];

// Create logger instance
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
  levels,
  format,
  transports,
  // Handle uncaught exceptions and rejections
  exceptionHandlers: [
    new DailyRotateFile({
      ...fileTransportOptions,
      filename: path.join(logsDir, 'exceptions-%DATE%.log'),
    }),
  ],
  rejectionHandlers: [
    new DailyRotateFile({
      ...fileTransportOptions,
      filename: path.join(logsDir, 'rejections-%DATE%.log'),
    }),
  ],
});

// Add custom logging methods with enhanced formatting
const customLogger = {
  // Success logging
  success: (message, context = {}) => {
    logger.info(`✅ ${message}`, { context });
  },

  // Warning logging
  warning: (message, context = {}) => {
    logger.warn(`⚠️ ${message}`, { context });
  },

  // Error logging with error object support
  error: (message, errorOrContext = {}) => {
    const isError = errorOrContext instanceof Error;
    const context = isError ? { error: errorOrContext } : errorOrContext;
    logger.error(`❌ ${message}`, { context });
  },

  // Info logging
  info: (message, context = {}) => {
    logger.info(`ℹ️ ${message}`, { context });
  },

  // Debug logging
  debug: (message, context = {}) => {
    logger.debug(`🔍 ${message}`, { context });
  },

  // HTTP request logging
  http: (message, context = {}) => {
    logger.http(`🌐 ${message}`, { context });
  },

  // Verbose logging
  verbose: (message, context = {}) => {
    logger.verbose(`📝 ${message}`, { context });
  },

  // Performance logging
  performance: (message, duration, context = {}) => {
    logger.info(`⚡ ${message}`, { 
      context: { ...context, duration, type: 'performance' } 
    });
  },

  // Security logging
  security: (message, context = {}) => {
    logger.warn(`🔒 ${message}`, { 
      context: { ...context, type: 'security' } 
    });
  },

  // Set context for subsequent log messages
  setContext: (context) => {
    logger.defaultMeta = { ...logger.defaultMeta, ...context };
  },

  // Clear context from subsequent log messages
  clearContext: () => {
    logger.defaultMeta = {};
  }
};

// Request logging middleware with enhanced formatting
customLogger.requestLogger = (req, res, next) => {
  const start = Date.now();
  const requestId = req.headers['x-request-id'] || Math.random().toString(36).substring(7);
  
  // Add request ID to response headers
  res.setHeader('X-Request-ID', requestId);
  
  // Log request start
  customLogger.debug(`Request started: ${req.method} ${req.url}`, {
    requestId,
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('user-agent'),
  });

  // Track response
  res.on('finish', () => {
    const duration = Date.now() - start;
    const context = {
      requestId,
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      user: req.user?.id || 'anonymous',
      userAgent: req.get('user-agent'),
      contentLength: res.get('content-length'),
    };

    const message = `${req.method} ${req.url}`;

    if (res.statusCode >= 500) {
      customLogger.error(`Request failed: ${message}`, context);
    } else if (res.statusCode >= 400) {
      customLogger.warning(`Request warning: ${message}`, context);
    } else {
      customLogger.http(`Request completed: ${message}`, context);
    }

    // Log performance if request took longer than 1 second
    if (duration > 1000) {
      customLogger.performance(`Slow request: ${message}`, duration, context);
    }
  });

  next();
};

// Export the enhanced logger
module.exports = customLogger; 