const express = require('express');
const router = express.Router();
const { authenticateUser } = require('../../middleware/authMiddleware');
const User = require('../../models/User');
const logger = require('../../config/logger');
const { AppError, ERROR_TYPES } = require('../../middleware/errorHandler');
const rateLimit = require('express-rate-limit');

// Rate limiter for session management
const sessionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 attempts per window
    message: { error: 'Too many attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
        next(new AppError('Too many attempts', 429, ERROR_TYPES.RATE_LIMIT));
    }
});

// Helper function to format IP address
const formatIP = (ip) => {
    if (ip === '::1' || ip === '127.0.0.1') {
        return 'Localhost';
    }
    return ip;
};

// Helper function to format date
const formatDate = (date) => {
    if (!date) return 'Active now';
    const now = new Date();
    const sessionDate = new Date(date);
    const diffInMinutes = Math.floor((now - sessionDate) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Active now';
    if (diffInMinutes < 60) return `${diffInMinutes} minutes ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)} hours ago`;
    return sessionDate.toLocaleString();
};

// Helper function to detect browser
const detectBrowser = (userAgent) => {
    if (!userAgent) return 'Unknown Browser';
    
    // Arc Browser - Arc uses a Chrome-based user agent but can be identified by its version
    if (userAgent.includes('Chrome/137.0.0.0')) {
        return 'Arc Browser';
    }
    
    // Chrome
    if (userAgent.includes('Chrome/') && !userAgent.includes('Chromium/') && !userAgent.includes('Edg/') && !userAgent.includes('OPR/')) {
        return 'Chrome';
    }
    
    // Firefox
    if (userAgent.includes('Firefox/')) {
        return 'Firefox';
    }
    
    // Safari
    if (userAgent.includes('Safari/') && !userAgent.includes('Chrome/')) {
        return 'Safari';
    }
    
    // Edge
    if (userAgent.includes('Edg/')) {
        return 'Edge';
    }
    
    // Opera
    if (userAgent.includes('OPR/')) {
        return 'Opera';
    }
    
    // Brave
    if (userAgent.includes('Brave/')) {
        return 'Brave';
    }
    
    // Chromium
    if (userAgent.includes('Chromium/')) {
        return 'Chromium';
    }

    // Log the user agent for debugging
    logger.debug('Unrecognized user agent:', userAgent);
    
    return 'Unknown Browser';
};

// Helper function to detect OS
const detectOS = (userAgent) => {
    if (!userAgent) return 'Unknown OS';
    
    if (userAgent.includes('Mac OS X')) {
        return 'macOS';
    }
    if (userAgent.includes('Windows')) {
        return 'Windows';
    }
    if (userAgent.includes('Linux')) {
        return 'Linux';
    }
    if (userAgent.includes('Android')) {
        return 'Android';
    }
    if (userAgent.includes('iOS')) {
        return 'iOS';
    }
    
    return 'Unknown OS';
};

// Get all active sessions
router.get('/', authenticateUser, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        const userAgent = req.headers['user-agent'];

        // Get current session info
        const currentSession = {
            id: req.sessionID,
            deviceInfo: {
                browser: detectBrowser(userAgent),
                os: detectOS(userAgent),
                ip: formatIP(req.ip)
            },
            lastActive: new Date(),
            isCurrent: true
        };

        // Get other active sessions from the database
        const otherSessions = (user.activeSessions || []).map(session => ({
            ...session,
            deviceInfo: {
                ...session.deviceInfo,
                ip: formatIP(session.deviceInfo.ip)
            },
            lastActive: formatDate(session.lastActive)
        }));

        const sessions = [currentSession, ...otherSessions];

        res.json({
            success: true,
            data: sessions
        });
    } catch (error) {
        next(error);
    }
});

// Revoke a specific session
router.delete('/:sessionId', authenticateUser, sessionLimiter, async (req, res, next) => {
    try {
        const { sessionId } = req.params;
        const user = await User.findById(req.user.id);
        
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        // Don't allow revoking the current session
        if (sessionId === req.sessionID) {
            throw new AppError('Cannot revoke current session', 400, ERROR_TYPES.VALIDATION);
        }

        // Remove the session from active sessions
        user.activeSessions = (user.activeSessions || []).filter(
            session => session.id !== sessionId
        );

        await user.save();

        res.json({
            success: true,
            message: 'Session revoked successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Revoke all other sessions
router.delete('/', authenticateUser, sessionLimiter, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        // Keep only the current session
        user.activeSessions = (user.activeSessions || []).filter(
            session => session.id === req.sessionID
        );

        await user.save();

        res.json({
            success: true,
            message: 'All other sessions revoked successfully'
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router; 