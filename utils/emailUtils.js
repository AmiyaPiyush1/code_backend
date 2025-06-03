const nodemailer = require('nodemailer');
const logger = require('../config/logger');

// Create reusable transporter
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_APP_PASSWORD
    }
});

// Send verification email
const sendVerificationEmail = async (email, token) => {
    try {
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
        const mailOptions = {
            from: `"CodeStream" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verify Your Email Address',
            html: `
                <div style="font-family:system-ui,-apple-system,sans-serif;max-width:500px;margin:20px auto;padding:20px;background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.05)">
                    <h1 style="color:#3F79DA;font-size:20px;margin:0 0 15px">Verify Your Email Address</h1>
                    <p style="color:#4a5568;font-size:15px;line-height:1.5;margin:0 0 20px">Click the button below to verify your email address.</p>
                    <div style="text-align:center;margin:25px 0">
                        <a href="${verificationUrl}" style="background:#3F79DA;color:#fff;padding:10px 25px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:500">Verify Email</a>
                    </div>
                    <div style="background:#f8fafc;border-radius:4px;padding:12px;margin-top:20px">
                        <p style="color:#718096;font-size:13px;margin:0"><strong>Note:</strong> Link expires in 24 hours.</p>
                    </div>
                    <div style="text-align:center;margin-top:20px;color:#a0aec0;font-size:12px">
                        &copy; ${new Date().getFullYear()} CodeStream
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        logger.info('Verification email sent successfully', { email });
    } catch (error) {
        logger.error('Failed to send verification email', { email, error: error.message });
        throw new Error('Failed to send verification email');
    }
};

module.exports = {
    sendVerificationEmail
}; 