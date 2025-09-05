const mongoose = require("mongoose");
const logger = require("./logger");
require("dotenv").config();

// Connection state tracking
let isConnecting = false;
let connectionAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_INTERVAL = 5000;

// MongoDB Connection Function
const connectDB = async () => {
    if (isConnecting) {
        logger.warning("Connection attempt already in progress");
        return;
    }

    if (connectionAttempts >= MAX_RECONNECT_ATTEMPTS) {
        logger.error("Maximum reconnection attempts reached");
        throw new Error("Maximum reconnection attempts reached");
    }

    isConnecting = true;
    connectionAttempts++;

    try {
        const options = {
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 30000,
            maxPoolSize: 20, // Increased for better concurrency
            minPoolSize: 10, // Increased for better availability
            autoIndex: process.env.NODE_ENV === 'development', // Only create indexes in development
            retryWrites: true,
            retryReads: true,
            family: 4,
            heartbeatFrequencyMS: 10000,
            compressors: ['zlib'], // Enable compression
            zlibCompressionLevel: 9, // Maximum compression
            maxIdleTimeMS: 60000, // Close idle connections after 1 minute
            waitQueueTimeoutMS: 10000, // Wait queue timeout
            monitorCommands: true // Enable command monitoring
        };

        const uri = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/authDB";

        // Set mongoose options
        mongoose.set('strictQuery', true);
        mongoose.set('debug', process.env.NODE_ENV === 'development');

        await mongoose.connect(uri, options);

        logger.success(`Successfully connected to MongoDB (Attempt ${connectionAttempts})`);
        connectionAttempts = 0; // Reset counter on successful connection
    } catch (error) {
        logger.error(`MongoDB Connection Error (Attempt ${connectionAttempts}): ${error.message}`);
        throw error;
    } finally {
        isConnecting = false;
    }
};

// Connection Monitoring
const monitorConnection = () => {
    try {
        if (!mongoose.connection || !mongoose.connection.client) {
            logger.warning('MongoDB connection not yet established');
            return;
        }

        const stats = {
            connections: mongoose.connection.client.topology?.s?.pool?.size || 0,
            available: mongoose.connection.client.topology?.s?.pool?.available || 0,
            pending: mongoose.connection.client.topology?.s?.pool?.pending || 0,
            max: mongoose.connection.client.topology?.s?.pool?.max || 0
        };

        logger.info(`MongoDB Pool Stats: ${JSON.stringify(stats)}`);
    } catch (error) {
        logger.error('Error monitoring MongoDB connection:', error.message);
    }
};

// MongoDB Connection Event Listeners
mongoose.connection.on("connected", () => {
    logger.success("MongoDB connection established");
    // Start periodic monitoring only after connection is established
    setTimeout(() => {
        setInterval(monitorConnection, 30000);
    }, 5000); // Wait 5 seconds before starting monitoring
});

mongoose.connection.on("error", (err) => {
    logger.error(`MongoDB error: ${err.message}`);
    if (err.name === 'MongoServerSelectionError') {
        logger.error("Could not connect to any MongoDB server");
    }
});

mongoose.connection.on("disconnected", () => {
    logger.warning("MongoDB disconnected. Reconnecting...");
    if (connectionAttempts < MAX_RECONNECT_ATTEMPTS) {
        setTimeout(() => {
            connectDB().catch(err => {
                logger.error(`Failed to reconnect to MongoDB: ${err.message}`);
            });
        }, RECONNECT_INTERVAL);
    } else {
        logger.error("Maximum reconnection attempts reached");
    }
});

// Handle process termination
const gracefulShutdown = async () => {
    try {
        logger.info("Closing MongoDB connection...");
        await mongoose.connection.close();
        logger.success("MongoDB connection closed gracefully");
        process.exit(0);
    } catch (err) {
        logger.error(`Error closing MongoDB connection: ${err.message}`);
        process.exit(1);
    }
};

// Handle various termination signals
process.on("SIGINT", gracefulShutdown);
process.on("SIGTERM", gracefulShutdown);
process.on("SIGQUIT", gracefulShutdown);

module.exports = connectDB;