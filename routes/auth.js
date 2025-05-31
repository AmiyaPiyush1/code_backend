const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { authenticateUser } = require('../middleware/authMiddleware');
const logger = require('../config/logger');
const crypto = require('crypto');
const { AppError, ERROR_TYPES } = require('../middleware/errorHandler');

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

// Google OAuth routes
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback',
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

// Get current user data
router.get('/me', authenticateUser, async (req, res, next) => {
    try {
        logger.info('Fetching user data for ID:', req.user.id);
        
        if (!req.user || !req.user.id) {
            logger.error('Invalid user data in request:', { user: req.user });
            throw new AppError('Invalid user data', 401, ERROR_TYPES.AUTHENTICATION);
        }

        const user = await User.findById(req.user.id)
            .select('+googleId +githubId +verificationToken +verificationTokenExpiry +resetToken +resetTokenExpiry')
            .select('-password')
            .lean(); // Use lean() to get plain JavaScript object
            
        if (!user) {
            logger.error('User not found for ID:', req.user.id);
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

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

module.exports = router; 