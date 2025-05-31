const nodemailer = require('nodemailer');
const logger = require('./logger');

// Email configuration constants
const EMAIL_CONFIG = {
    POOL_SIZE: 10, // Increased pool size for better concurrency
    MAX_MESSAGES_PER_CONNECTION: 100,
    RATE_LIMIT: {
        DELTA: 1000, // 1 second
        MAX_MESSAGES: 10 // Increased from 5 to 10 messages per second
    },
    RETRY: {
        MAX_ATTEMPTS: 3,
        DELAY: 1000 // 1 second
    },
    TIMEOUT: 10000 // 10 seconds
};

// Create reusable transporter object using SMTP transport with optimized settings
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_APP_PASSWORD
    },
    tls: {
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2' // Enforce minimum TLS version
    },
    pool: true,
    maxConnections: EMAIL_CONFIG.POOL_SIZE,
    maxMessages: EMAIL_CONFIG.MAX_MESSAGES_PER_CONNECTION,
    rateDelta: EMAIL_CONFIG.RATE_LIMIT.DELTA,
    rateLimit: EMAIL_CONFIG.RATE_LIMIT.MAX_MESSAGES,
    socketTimeout: EMAIL_CONFIG.TIMEOUT,
    connectionTimeout: EMAIL_CONFIG.TIMEOUT,
    greetingTimeout: EMAIL_CONFIG.TIMEOUT,
    debug: process.env.NODE_ENV === 'development'
});

// Email sending statistics
const emailStats = {
    sent: 0,
    failed: 0,
    lastError: null,
    lastSent: null
};

// Monitor email sending statistics
const monitorEmailStats = () => {
    logger.info('Email Statistics:', {
        sent: emailStats.sent,
        failed: emailStats.failed,
        lastError: emailStats.lastError,
        lastSent: emailStats.lastSent
    });
};

// Verify transporter configuration with retry mechanism
const verifyTransporter = async (attempts = 0) => {
    try {
        await transporter.verify();
        logger.info('Email server is ready to send messages');
        return true;
    } catch (error) {
        if (attempts < EMAIL_CONFIG.RETRY.MAX_ATTEMPTS) {
            logger.warning(`Email verification attempt ${attempts + 1} failed, retrying...`);
            await new Promise(resolve => setTimeout(resolve, EMAIL_CONFIG.RETRY.DELAY));
            return verifyTransporter(attempts + 1);
        }
        logger.error('Email configuration error:', error);
        throw error;
    }
};

// Initialize email service
verifyTransporter().catch(error => {
    logger.error('Failed to initialize email service:', error);
});

// Send email with retry mechanism
const sendEmail = async (mailOptions, attempts = 0) => {
    try {
        const info = await transporter.sendMail(mailOptions);
        emailStats.sent++;
        emailStats.lastSent = new Date();
        logger.info('Email sent successfully:', info.messageId);
        return info;
    } catch (error) {
        emailStats.failed++;
        emailStats.lastError = error.message;

        if (attempts < EMAIL_CONFIG.RETRY.MAX_ATTEMPTS) {
            logger.warning(`Email send attempt ${attempts + 1} failed, retrying...`);
            await new Promise(resolve => setTimeout(resolve, EMAIL_CONFIG.RETRY.DELAY));
            return sendEmail(mailOptions, attempts + 1);
        }

        logger.error('Failed to send email after multiple attempts:', error);
        throw new Error('Failed to send email');
    }
};

const sendPasswordResetEmail = async (email, resetToken) => {
    try {
        if (!process.env.EMAIL_USER || !process.env.EMAIL_APP_PASSWORD) {
            throw new Error('Email configuration is missing');
        }

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

        const mailOptions = {
            from: `"CodeStream Support" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Reset Your CodeStream Password',
            html: `
                <div style="font-family:system-ui,-apple-system,sans-serif;max-width:500px;margin:20px auto;padding:20px;background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.05)">
                    <h1 style="color:#3F79DA;font-size:20px;margin:0 0 15px">Reset Your Password</h1>
                    <p style="color:#4a5568;font-size:15px;line-height:1.5;margin:0 0 20px">Click the button below to create a new password.</p>
                    <div style="text-align:center;margin:25px 0">
                        <a href="${resetUrl}" style="background:#3F79DA;color:#fff;padding:10px 25px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:500">Reset Password</a>
                    </div>
                    <div style="background:#f8fafc;border-radius:4px;padding:12px;margin-top:20px">
                        <p style="color:#718096;font-size:13px;margin:0"><strong>Note:</strong> Link expires in 1 hour.</p>
                    </div>
                    <div style="text-align:center;margin-top:20px;color:#a0aec0;font-size:12px">
                        &copy; ${new Date().getFullYear()} CodeStream
                    </div>
                </div>
            `
        };

        await sendEmail(mailOptions);
        return true;
    } catch (error) {
        logger.error('Error sending password reset email:', error);
        throw new Error('Failed to send reset email');
    }
};

// Start periodic monitoring
setInterval(monitorEmailStats, 300000); // Log stats every 5 minutes

module.exports = {
    sendPasswordResetEmail,
    emailStats,
    verifyTransporter
}; 