const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const logger = require("../../config/logger");
const User = require("../../models/User");
const { sendPasswordResetEmail } = require('../../config/emailConfig');
const { AppError, ERROR_TYPES } = require('../../middleware/errorHandler');
const crypto = require('crypto');
require("dotenv").config();

const router = express.Router();
const SECRET_KEY = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const TOKEN_EXPIRY = "1h";
const REFRESH_TOKEN_EXPIRY = "7d";

// Rate Limiter: Prevent brute-force attacks with user-based tracking
const loginAttempts = new Map(); // Store failed login attempts per user

const loginLimiter = rateLimit({
    windowMs: 150 * 60 * 1000, // 150 minutes
    max: process.env.NODE_ENV === 'development' ? 0 : 500000, // 0 means no limit in development
    message: { error: "Too many login attempts, please try again later." },
    standardHeaders: true, // Send rate limit info in headers
    legacyHeaders: false,
    keyGenerator: (req) => {
        // Use email as the key for rate limiting
        return req.body.email || req.ip;
    },
    skip: (req) => {
        // Skip rate limiting for successful logins
        return req.body.email && loginAttempts.get(req.body.email)?.success;
    },
    handler: (req, res, next, options) => {
        const retryAfter = Math.ceil(options.windowMs / 1000);
        res.setHeader('Retry-After', retryAfter);
        next(new AppError('Too many login attempts', 429, ERROR_TYPES.RATE_LIMIT));
    }
});

// Login route
router.post("/", async (req, res, next) => {
    try {
        const { email, password, twoFactorCode } = req.body;
        logger.info('Login attempt:', { email: email.toLowerCase().trim() });

        // Validate input
        if (!email || !password) {
            throw new AppError('Email and password are required', 400, ERROR_TYPES.VALIDATION);
        }

        // Find user and explicitly select password field
        const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password +recoveryCodes');
        logger.info('User lookup result:', { 
            found: !!user,
            hasPassword: !!user?.password,
            email: email.toLowerCase().trim(),
            passwordLength: user?.password?.length
        });

        if (!user) {
            throw new AppError('Invalid email or password', 401, ERROR_TYPES.AUTHENTICATION);
        }

        // Check if user is using Google or GitHub auth
        if (user.googleId || user.githubId) {
            throw new AppError('Please use Google or GitHub to login', 401, ERROR_TYPES.AUTHENTICATION);
        }

        // Verify password
        logger.info('Attempting password comparison for user:', { email: user.email });
        const isPasswordValid = await user.comparePassword(password);
        logger.info('Password comparison result:', { 
            email: user.email,
            isValid: isPasswordValid,
            hashedPasswordLength: user.password.length
        });

        if (!isPasswordValid) {
            // Track failed attempt
            const attempts = loginAttempts.get(email) || { count: 0, timestamp: Date.now() };
            attempts.count++;
            loginAttempts.set(email, attempts);

            throw new AppError('Invalid email or password', 401, ERROR_TYPES.AUTHENTICATION);
        }

        // Check if 2FA is enabled
        if (user.twoFactorEnabled) {
            if (!twoFactorCode) {
                // Return 2FA required response
                return res.status(200).json({
                    success: false,
                    requiresTwoFactor: true,
                    message: '2FA code required'
                });
            }

            // Verify 2FA code
            const is2FAValid = user.verify2FACode(twoFactorCode);
            if (!is2FAValid) {
                throw new AppError('Invalid 2FA code', 401, ERROR_TYPES.AUTHENTICATION);
            }
        }

        // Generate tokens
        const accessToken = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: TOKEN_EXPIRY }
        );

        const refreshToken = jwt.sign(
            { id: user._id },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: REFRESH_TOKEN_EXPIRY }
        );

        // Set cookies
        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 3600000 // 1 hour
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 3600000 // 7 days
        });

        // Update last login and reset login attempts
        user.lastLogin = new Date();
        await user.save();
        loginAttempts.delete(email);

        // Return success response
        res.json({
            success: true,
            data: {
                user: {
                    id: user._id,
                    email: user.email,
                    name: user.name,
                    picture: user.picture,
                    isAdmin: user.isAdmin,
                    permissions: user.permissions,
                    twoFactorEnabled: user.twoFactorEnabled
                },
                accessToken,
                refreshToken
            }
        });
    } catch (error) {
        next(error);
    }
});

// Password reset request
router.post("/reset-password", async (req, res, next) => {
    try {
        const { email } = req.body;

        if (!email) {
            throw new AppError('Email is required', 400, ERROR_TYPES.VALIDATION);
        }

        logger.info('Password reset requested for email:', { email: email.toLowerCase().trim() });

        const user = await User.findOne({ email: email.toLowerCase().trim() });
        if (!user) {
            // Don't reveal if email exists
            return res.json({
                success: true,
                message: 'If an account exists with this email, you will receive a password reset link'
            });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000; // 1 hour

        // Store the email with the token for verification
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = resetTokenExpiry;
        await user.save();

        logger.info('Reset token generated for user:', { 
            email: user.email,
            token: resetToken.substring(0, 10) + '...'
        });

        // Send reset email
        await sendPasswordResetEmail(user.email, resetToken);

        res.json({
            success: true,
            message: 'If an account exists with this email, you will receive a password reset link'
        });
    } catch (error) {
        next(error);
    }
});

// Reset password with token
router.post("/reset-password/:token", async (req, res, next) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        if (!password) {
            throw new AppError('New password is required', 400, ERROR_TYPES.VALIDATION);
        }

        logger.info('Attempting password reset with token:', { token: token.substring(0, 10) + '...' });

        // Find user by token and ensure token hasn't expired
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        }).select('+password');

        if (!user) {
            logger.warning('Invalid or expired reset token');
            throw new AppError('Invalid or expired reset token', 400, ERROR_TYPES.VALIDATION);
        }

        logger.info('Found user for password reset:', { 
            email: user.email,
            token: token.substring(0, 10) + '...'
        });

        // Update password
        user.password = password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        
        try {
            await user.save();
            logger.info('Password reset successful for user:', { 
                email: user.email,
                token: token.substring(0, 10) + '...'
            });
        } catch (saveError) {
            logger.error('Error saving password reset:', { 
                error: saveError.message,
                email: user.email
            });
            throw new AppError('Failed to update password', 500, ERROR_TYPES.SERVER);
        }

        res.json({
            success: true,
            message: 'Password has been reset successfully'
        });
    } catch (error) {
        logger.error('Password reset error:', { 
            error: error.message,
            stack: error.stack
        });
        next(error);
    }
});

module.exports = router;