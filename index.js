require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { corsOptions, logCorsRequests } = require("./config/corsConfig");
const { startServer } = require("./config/portConfig");
const cookieParser = require("cookie-parser");
const session = require('express-session');
const passport = require('./config/passport');
const helmet = require('helmet');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');
const logger = require('./config/logger');

// Import routes
const loginRoute = require("./routes/auth/login");
const signupRoute = require("./routes/auth/signup");
const profileRoute = require("./routes/auth/profile");
const generateRoute = require("./routes/debugger/generate");
const authRoute = require("./routes/auth");
const geminiRoute = require("./routes/gemini");

// Import configurations
const connectDB = require("./config/database");
const { errorHandler, AppError, ERROR_TYPES } = require('./middleware/errorHandler');

const app = express();

// Port configuration
const DEFAULT_PORT = process.env.PORT || 3000;
const PORT_RANGE_START = 3000;
const PORT_RANGE_END = 3200;

// Global error handling for uncaught exceptions
process.on('uncaughtException', (err) => {
    logger.error('UNCAUGHT EXCEPTION!', {
        error: err.message,
        stack: err.stack
    });
    process.exit(1);
});

// Connect to MongoDB with retry mechanism
const connectWithRetry = async () => {
    try {
        await connectDB();
        logger.success('Successfully connected to MongoDB');
    } catch (err) {
        logger.error('MongoDB connection failed', {
            error: err.message,
            retrying: true
        });
        setTimeout(connectWithRetry, 5000);
    }
};

connectWithRetry();

// Basic root route (optional)
app.get("/", (req, res) => {
    res.send("🚀 Backend running successfully on Render");
});

// Security Middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/api/auth/login'
});
app.use('/api/', limiter);

// Compression middleware
app.use(compression());

// Body parser
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// CORS
app.use(cors(corsOptions));
app.use(logCorsRequests);
app.options('*', cors(corsOptions));

// Session
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
    },
    name: 'sessionId',
    rolling: true
}));

// Passport
app.use(passport.initialize());
app.use(passport.session());

// Request Logging
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.url}`, {
        ip: req.ip,
        userAgent: req.get('user-agent')
    });
    next();
});

// Routes
app.use("/api/auth", profileRoute);
app.use("/api/auth", authRoute);
app.use("/api/auth", loginRoute);
app.use("/api/auth", signupRoute);
app.use("/api/gemini", geminiRoute);
app.use("/", generateRoute.router);

// Health route
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        timestamp: new Date(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: process.env.NODE_ENV
    });
});

// 404 handler
app.use((req, res, next) => {
    logger.warning('Route not found', {
        method: req.method,
        url: req.url,
        ip: req.ip
    });

    const err = new AppError('Route not found', 404, ERROR_TYPES.NOT_FOUND);
    err.stack = undefined;
    next(err);
});

// Error handler
app.use(errorHandler);

// Unhandled promise rejections
process.on('unhandledRejection', (err) => {
    logger.error('UNHANDLED REJECTION!', {
        error: err.message,
        stack: err.stack
    });
    process.exit(1);
});

// Graceful shutdown
const gracefulShutdown = () => {
    logger.info('Received shutdown signal');
    process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start the server
(async () => {
    try {
        await startServer(app, DEFAULT_PORT, PORT_RANGE_START, PORT_RANGE_END);
    } catch (error) {
        logger.error('Failed to start server', {
            error: error.message,
            stack: error.stack
        });
        process.exit(1);
    }
})();
