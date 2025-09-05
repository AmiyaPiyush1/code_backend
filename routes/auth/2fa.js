const express = require('express');
const router = express.Router();
const { authenticateUser } = require('../../middleware/authMiddleware');
const User = require('../../models/User');
const logger = require('../../config/logger');
const { AppError, ERROR_TYPES } = require('../../middleware/errorHandler');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// Rate limiter for 2FA setup and verification
const twoFALimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: { error: 'Too many attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
        next(new AppError('Too many attempts', 429, ERROR_TYPES.RATE_LIMIT));
    }
});

// Get 2FA status and recovery options
router.get('/status', authenticateUser, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        res.json({
            success: true,
            data: {
                isEnabled: !!user.twoFactorSecret,
                hasRecoveryCodes: user.recoveryCodes && user.recoveryCodes.length > 0,
                lastUsed: user.last2FAUsed,
                backupMethods: user.backupMethods || []
            }
        });
    } catch (error) {
        next(error);
    }
});

// Setup 2FA
router.post('/setup', authenticateUser, twoFALimiter, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        if (user.twoFactorSecret) {
            throw new AppError('2FA is already enabled', 400, ERROR_TYPES.VALIDATION);
        }

        // Generate secret
        const secret = speakeasy.generateSecret({
            length: 20,
            name: `CodeStream:${user.email}`,
            issuer: 'CodeStream'
        });

        // Generate QR code
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        // Store temporary secret
        user.twoFactorSecret = secret.base32;
        user.twoFactorEnabled = false;
        await user.save();

        res.json({
            success: true,
            data: {
                qrCode,
                secretKey: secret.base32,
                otpauth_url: secret.otpauth_url
            }
        });
    } catch (error) {
        next(error);
    }
});

// Verify and enable 2FA
router.post('/verify', authenticateUser, twoFALimiter, async (req, res, next) => {
    try {
        const { code, secretKey } = req.body;
        if (!code || !secretKey) {
            throw new AppError('Verification code and secret key are required', 400, ERROR_TYPES.VALIDATION);
        }

        const user = await User.findById(req.user.id);
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        // Check if user has a temporary secret stored
        if (!user.twoFactorSecret) {
            throw new AppError('2FA setup not initiated', 400, ERROR_TYPES.VALIDATION);
        }

        // Verify the code
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: code,
            window: 1 // Allow 30 seconds clock skew
        });

        if (!verified) {
            throw new AppError('Invalid verification code', 400, ERROR_TYPES.VALIDATION);
        }

        // Enable 2FA
        user.twoFactorEnabled = true;
        user.last2FAUsed = new Date();
        await user.save();

        // Generate recovery codes
        const recoveryCodes = Array.from({ length: 10 }, () => 
            crypto.randomBytes(4).toString('hex').toUpperCase()
        );

        // Store recovery codes (hashed)
        user.recoveryCodes = recoveryCodes.map(code => 
            crypto.createHash('sha256').update(code).digest('hex')
        );
        await user.save();

        res.json({
            success: true,
            data: {
                recoveryCodes,
                message: '2FA has been enabled successfully'
            }
        });
    } catch (error) {
        next(error);
    }
});

// Generate new recovery codes
router.post('/recovery-codes', authenticateUser, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        if (!user.twoFactorEnabled) {
            throw new AppError('2FA is not enabled', 400, ERROR_TYPES.VALIDATION);
        }

        // Generate new recovery codes
        const recoveryCodes = Array.from({ length: 10 }, () => 
            crypto.randomBytes(4).toString('hex').toUpperCase()
        );

        // Store recovery codes (hashed)
        user.recoveryCodes = recoveryCodes.map(code => 
            crypto.createHash('sha256').update(code).digest('hex')
        );
        await user.save();

        res.json({
            success: true,
            data: {
                recoveryCodes,
                message: 'New recovery codes generated successfully'
            }
        });
    } catch (error) {
        next(error);
    }
});

// Verify recovery code
router.post('/verify-recovery', authenticateUser, async (req, res, next) => {
    try {
        const { recoveryCode } = req.body;
        if (!recoveryCode) {
            throw new AppError('Recovery code is required', 400, ERROR_TYPES.VALIDATION);
        }

        const user = await User.findById(req.user.id);
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        if (!user.twoFactorEnabled) {
            throw new AppError('2FA is not enabled', 400, ERROR_TYPES.VALIDATION);
        }

        const hashedCode = crypto.createHash('sha256').update(recoveryCode).digest('hex');
        const codeIndex = user.recoveryCodes.indexOf(hashedCode);

        if (codeIndex === -1) {
            throw new AppError('Invalid recovery code', 400, ERROR_TYPES.VALIDATION);
        }

        // Remove used recovery code
        user.recoveryCodes.splice(codeIndex, 1);
        await user.save();

        res.json({
            success: true,
            message: 'Recovery code verified successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Disable 2FA
router.post('/disable', authenticateUser, twoFALimiter, async (req, res, next) => {
    try {
        const { code } = req.body;
        if (!code) {
            throw new AppError('Verification code is required', 400, ERROR_TYPES.VALIDATION);
        }

        const user = await User.findById(req.user.id);
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        if (!user.twoFactorEnabled) {
            throw new AppError('2FA is not enabled', 400, ERROR_TYPES.VALIDATION);
        }

        // Verify the code
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: code,
            window: 1 // Allow 30 seconds clock skew
        });

        if (!verified) {
            throw new AppError('Invalid verification code', 400, ERROR_TYPES.VALIDATION);
        }

        // Disable 2FA
        user.twoFactorSecret = undefined;
        user.twoFactorEnabled = false;
        user.recoveryCodes = [];
        user.backupMethods = [];
        await user.save();

        res.json({
            success: true,
            message: '2FA has been disabled successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Add backup method (e.g., phone number)
router.post('/backup-method', authenticateUser, async (req, res, next) => {
    try {
        const { type, value } = req.body;
        if (!type || !value) {
            throw new AppError('Backup method type and value are required', 400, ERROR_TYPES.VALIDATION);
        }

        const user = await User.findById(req.user.id);
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        if (!user.twoFactorEnabled) {
            throw new AppError('2FA is not enabled', 400, ERROR_TYPES.VALIDATION);
        }

        // Initialize backupMethods array if it doesn't exist
        if (!user.backupMethods) {
            user.backupMethods = [];
        }

        // Add new backup method
        user.backupMethods.push({
            type,
            value,
            verified: false,
            addedAt: new Date()
        });

        await user.save();

        res.json({
            success: true,
            message: 'Backup method added successfully'
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router; 