require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const passport = require('./config/passport');
const helmet = require('helmet');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');
const logger = require('./config/logger');

const { corsOptions, logCorsRequests } = require("./config/corsConfig");

// Import routes
const loginRoute = require("./routes/auth/login");
const signupRoute = require("./routes/auth/signup");
const profileRoute = require("./routes/auth/profile");
const generateRoute = require("./routes/debugger/generate");
const authRoute = require("./routes/auth");
const geminiRoute = require("./routes/gemini");

// Import DB config + error handling
const connectDB = require("./config/database");
const { errorHandler, AppError, ERROR_TYPES } = require('./middleware/errorHandler');

const app = express();

// ==========================
//  GLOBAL ERROR HANDLING
// ==========================
process.on('uncaughtException', (err) => {
    logger.error('UNCAUGHT EXCEPTION!', {
        error: err.message,
        stack: err.stack
    });
    process.exit(1);
});

// ==========================
//  CONNECT TO MONGO
// ==========================
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

// ==========================
//   BASIC ROOT ROUTE
// ==========================
app.get("/", (req, res) => {
    res.send("🚀 Backend running successfully on Render");
});

// ==========================
//  SECURITY MIDDLEWARE
// ==========================
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// ==========================
//  RATE LIMITING
// ==========================
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/api/auth/login'
});
app.use('/api/', limiter);

// ==========================
//  BODY PARSING
// ==========================
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// ==========================
//  CORS
// ==========================
app.use(cors(corsOptions));
app.use(logCorsRequests);
app.options('*', cors(corsOptions));

// ==========================
//  SESSION
// ==========================
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

// ==========================
//  PASSPORT
// ==========================
app.use(passport.initialize());
app.use(passport.session());

// ==========================
//  REQUEST LOGGING
// ==========================
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.url}`, {
        ip: req.ip,
        userAgent: req.get('user-agent')
    });
    next();
});

// ==========================
//  ROUTES
// ==========================
app.use("/api/auth", profileRoute);
app.use("/api/auth", authRoute);
app.use("/api/auth", loginRoute);
app.use("/api/auth", signupRoute);
app.use("/api/gemini", geminiRoute);
app.use("/", generateRoute.router);

// ==========================
//  HEALTH CHECK
// ==========================
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        timestamp: new Date(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV
    });
});

// ==========================
//  404 HANDLER
// ==========================
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

// ==========================
//  ERROR HANDLER
// ==========================
app.use(errorHandler);

// ==========================
//  UNHANDLED PROMISE REJECTION
// ==========================
process.on('unhandledRejection', (err) => {
    logger.error('UNHANDLED REJECTION!', {
        error: err.message,
        stack: err.stack
    });
    process.exit(1);
});

// ==========================
//  GRACEFUL SHUTDOWN
// ==========================
process.on('SIGTERM', () => {
    logger.info('Received SIGTERM — Shutting down gracefully');
    process.exit(0);
});
process.on('SIGINT', () => {
    logger.info('Received SIGINT — Shutting down gracefully');
    process.exit(0);
});

// ==========================
//  START SERVER (Render)
// ==========================
const PORT = process.env.PORT;

app.listen(PORT, () => {
    logger.success(`🚀 Server running on Render (port: ${PORT})`);
});
