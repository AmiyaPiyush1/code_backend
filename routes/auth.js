const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { authenticateUser } = require('../middleware/authMiddleware');
const logger = require('../config/logger');
const crypto = require('crypto');
const { AppError, ERROR_TYPES } = require('../middleware/errorHandler');
const { sendVerificationEmail } = require('../utils/emailUtils');
const redisClient = require('../config/redis');
const rateLimit = require('express-rate-limit');

// Import route modules
const loginRoute = require('./auth/login');
const signupRoute = require('./auth/signup');
const profileRoute = require('./auth/profile');
const twoFARoute = require('./auth/2fa');
const sessionsRoute = require('./auth/sessions');

// Use route modules
router.use('/login', loginRoute);
router.use('/signup', signupRoute);
router.use('/profile', profileRoute);
router.use('/2fa', twoFARoute);
router.use('/sessions', sessionsRoute);

// Add rate limiting for Google authentication
const googleAuthLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 500, // 5 requests per minute
  message: 'Too many login attempts, please try again later',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many login attempts, please try again later',
      retryAfter: Math.ceil(res.getHeader('Retry-After') || 60)
    });
  }
});

// Google OAuth routes
router.get('/google',
  googleAuthLimiter,
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback',
  googleAuthLimiter,
  passport.authenticate('google', { failureRedirect: '/login' }),
  async (req, res) => {
    try {
      // Generate tokens
      const accessToken = jwt.sign(
        { id: req.user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      const refreshToken = jwt.sign(
        { id: req.user._id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
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

      // Update last login
      await User.findByIdAndUpdate(req.user._id, {
        lastLogin: new Date()
      });

      // Redirect to frontend with tokens
      res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}&refreshToken=${refreshToken}`);
    } catch (error) {
      logger.error('Google OAuth callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
    }
  }
);

// GitHub OAuth routes
router.get('/github',
  passport.authenticate('github', { scope: ['user:email'] })
);

router.get('/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  async (req, res) => {
    try {
      // Generate tokens
      const accessToken = jwt.sign(
        { id: req.user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      const refreshToken = jwt.sign(
        { id: req.user._id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
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

      // Update last login
      await User.findByIdAndUpdate(req.user._id, {
        lastLogin: new Date()
      });

      // Redirect to frontend with tokens
      res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}&refreshToken=${refreshToken}`);
    } catch (error) {
      logger.error('GitHub OAuth callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
    }
  }
);

// Logout route
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.clearCookie('refreshToken');
  res.json({ success: true, message: 'Logged out successfully' });
});

// Switch account route
router.get('/switch-account', (req, res, next) => {
  try {
    // Clear the current session
    req.session.destroy((err) => {
      if (err) {
        throw new AppError('Failed to destroy session', 500, ERROR_TYPES.AUTHENTICATION);
      }
      
      // Clear the token cookie
      res.clearCookie('token');
      res.clearCookie('refreshToken');
      
      // Redirect to login page
      res.redirect(`${process.env.FRONTEND_URL}/login`);
    });
  } catch (error) {
    next(error);
  }
});

// Add rate limiting for background refreshes
const backgroundRefreshLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 2, // 2 requests per minute for background refreshes
  message: 'Too many background refresh requests, please try again later'
});

// Get current user data
router.get('/me', authenticateUser, async (req, res, next) => {
    try {
        logger.info('Fetching user data for ID:', req.user.id);
        
        if (!req.user || !req.user.id) {
            logger.error('Invalid user data in request:', { user: req.user });
            throw new AppError('Invalid user data', 401, ERROR_TYPES.AUTHENTICATION);
        }

        // Apply rate limiting for background refreshes
        if (req.headers['x-request-type'] === 'background-refresh') {
            try {
                await backgroundRefreshLimiter(req, res, () => {});
            } catch (error) {
                if (error.statusCode === 429) {
                    // If rate limited, return cached data if available
                    const cacheKey = `user:${req.user.id}`;
                    const cachedUser = await redisClient.get(cacheKey);
                    if (cachedUser) {
                        return res.json({
                            success: true,
                            data: JSON.parse(cachedUser)
                        });
                    }
                }
                throw error;
            }
        }

        // Add cache check
        const cacheKey = `user:${req.user.id}`;
        const cachedUser = await redisClient.get(cacheKey);
        
        if (cachedUser) {
            logger.info('Serving user data from cache:', { userId: req.user.id });
            return res.json({
                success: true,
                data: JSON.parse(cachedUser)
            });
        }

        const user = await User.findById(req.user.id)
            .select('email name picture bio role isVerified createdAt updatedAt')
            .lean();
            
        if (!user) {
            logger.error('User not found for ID:', req.user.id);
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        // Cache the user data for 5 minutes
        await redisClient.setex(cacheKey, 300, JSON.stringify(user));

        logger.info('Successfully fetched user data:', {
            id: user._id,
            email: user.email,
            name: user.name
        });

        res.json({
            success: true,
            data: user
        });
    } catch (error) {
        logger.error('Error in /me endpoint:', {
            message: error.message,
            stack: error.stack,
            userId: req.user?.id,
            errorType: error.name,
            errorCode: error.code
        });

        if (error instanceof AppError) {
            next(error);
        } else if (error.name === 'CastError') {
            next(new AppError('Invalid user ID format', 400, ERROR_TYPES.VALIDATION));
        } else if (error.name === 'MongooseError') {
            next(new AppError('Database error', 500, ERROR_TYPES.DATABASE));
        } else {
            next(new AppError('Failed to fetch user data', 500, ERROR_TYPES.SERVER));
        }
    }
});

// Email verification route
router.get('/verify-email', async (req, res, next) => {
    try {
        const { token } = req.query;
        if (!token) {
            throw new AppError('Verification token is required', 400, ERROR_TYPES.VALIDATION);
        }

        // Hash the token before comparing
        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const user = await User.findOne({
            verificationToken: hashedToken,
            verificationTokenExpiry: { $gt: Date.now() }
        });

        if (!user) {
            throw new AppError('Invalid or expired verification token', 400, ERROR_TYPES.VALIDATION);
        }

        // Mark email as verified
        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpiry = undefined;
        await user.save();

        // Return success response
        res.json({
            success: true,
            message: 'Email verified successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Send verification email route
router.post('/send-verification', authenticateUser, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id)
            .select('+verificationToken +verificationTokenExpiry');

        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        if (user.isVerified) {
            throw new AppError('Email is already verified', 400, ERROR_TYPES.VALIDATION);
        }

        // Generate new verification token
        const verificationToken = user.generateVerificationToken();
        await user.save();

        // Send verification email
        await sendVerificationEmail(user.email, verificationToken);

        res.json({
            success: true,
            message: 'If an account exists with this email, you will receive a verification link'
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router; 