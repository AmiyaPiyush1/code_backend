const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const User = require("../../models/User");
const logger = require("../../config/logger");
const { AppError, ERROR_TYPES } = require('../../middleware/errorHandler');
const crypto = require('crypto');
require("dotenv").config();

const router = express.Router();
const SECRET_KEY = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const TOKEN_EXPIRY = "1h";
const REFRESH_TOKEN_EXPIRY = "7d";

// Rate Limiter to prevent mass signups
const signupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit to 5 signups per window per IP
    message: { error: "Too many signup attempts, please try again later." },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
        next(new AppError('Too many signup attempts', 429, ERROR_TYPES.RATE_LIMIT));
    }
});

// Helper function to handle MongoDB errors
const handleMongoError = (error) => {
    if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        return {
            status: 409,
            response: {
                success: false,
                error: `An account with this ${field} already exists`,
                suggestion: field === 'email' ? 'Please try logging in instead or use a different email address' : 'Please use a different value'
            }
        };
    }
    return {
        status: 500,
        response: {
            success: false,
            error: "An error occurred during signup",
            details: process.env.NODE_ENV === "development" ? error.message : undefined
        }
    };
};

// Signup Route with Enhanced Validation
router.post(
    "/signup",
    signupLimiter,
    [
        body("email")
            .isEmail().withMessage("Invalid email format")
            .normalizeEmail()
            .custom(async (email) => {
                const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
                if (existingUser) {
                    throw new Error('Email already in use');
                }
                return true;
            }),
        body("password")
            .isLength({ min: 8 }).withMessage("Password must be at least 8 characters long")
            .matches(/[A-Z]/).withMessage("Password must contain at least one uppercase letter")
            .matches(/[a-z]/).withMessage("Password must contain at least one lowercase letter")
            .matches(/[0-9]/).withMessage("Password must contain at least one number")
            .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)")
            .custom((value) => {
                // Check for common passwords
                const commonPasswords = ['password123', '12345678', 'qwerty123'];
                if (commonPasswords.includes(value.toLowerCase())) {
                    throw new Error('Password is too common');
                }
                return true;
            }),
        body("name")
            .optional()
            .trim()
            .isLength({ min: 2, max: 50 }).withMessage("Name must be between 2 and 50 characters")
            .matches(/^[a-zA-Z\s\-']*$/).withMessage("Name can only contain letters, spaces, hyphens, and apostrophes")
    ],
    async (req, res, next) => {
        try {
            logger.setContext({ action: 'signup', email: req.body.email?.toLowerCase() });

            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                logger.warning('Validation errors during signup', { errors: errors.array() });
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { email, password, name } = req.body;

            // Generate profile picture
            const picture = `https://www.gravatar.com/avatar/${crypto.createHash('md5').update(email.toLowerCase().trim()).digest('hex')}?d=mp&s=200`;

            // Create new user with additional fields
            const user = new User({
                email: email.toLowerCase().trim(),
                password: password, // Pass the plain password, let the model handle hashing
                name: name || email.split('@')[0], // Use email username if name not provided
                picture,
                role: 'user',
                loginCount: 1, // Start with 1 since this is first login
                lastLogin: new Date(),
                createdAt: new Date(),
                updatedAt: new Date()
            });

            try {
                await user.save();
            } catch (saveError) {
                const { status, response } = handleMongoError(saveError);
                logger.warning('Error during user save', { error: saveError.message });
                return res.status(status).json(response);
            }

            // Generate JWT and Refresh Token
            const token = jwt.sign(
                { 
                    id: user._id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    picture: user.picture
                }, 
                SECRET_KEY, 
                { expiresIn: TOKEN_EXPIRY }
            );
            const refreshToken = jwt.sign(
                { id: user._id }, 
                REFRESH_SECRET, 
                { expiresIn: REFRESH_TOKEN_EXPIRY }
            );

            // Set tokens in secure HTTP-only cookies
            res.cookie("token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "Strict",
                maxAge: 3600000 // 1 hour
            });

            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "Strict",
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });

            logger.success('New user registered and logged in successfully', { email: user.email });
            res.status(201).json({ 
                success: true,
                message: "Registration successful and logged in",
                data: {
                    user: {
                        id: user._id,
                        email: user.email,
                        name: user.name,
                        picture: user.picture,
                        role: user.role,
                        lastLogin: user.lastLogin
                    },
                    token: token, // Send token in response body for frontend storage
                    refreshToken: refreshToken // Send refresh token for frontend storage
                }
            });

        } catch (error) {
            logger.error('Server error during signup', { 
                email: req.body.email?.toLowerCase(),
                error: error.message 
            });
            next(error);
        } finally {
            logger.clearContext();
        }
    }
);

module.exports = router;