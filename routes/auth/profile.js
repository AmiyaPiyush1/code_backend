const express = require("express");
const { authenticateUser } = require("../../middleware/authMiddleware");
const User = require('../../models/User');
const logger = require('../../config/logger');
const { AppError, ERROR_TYPES } = require('../../middleware/errorHandler');
const crypto = require('crypto');
const mongoose = require('mongoose');

const router = express.Router();

// Protected Route - User Profile
router.get("/profile", authenticateUser, async (req, res, next) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
            throw new AppError('Invalid user ID format', 400, ERROR_TYPES.VALIDATION);
        }

        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            throw new AppError('User not found', 404, ERROR_TYPES.NOT_FOUND);
        }

        res.json({ 
            message: `Welcome, ${user.email}`,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                picture: user.picture,
                googleId: user.googleId,
                githubId: user.githubId,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }
        });
    } catch (error) {
        next(error);
    }
});

// Get current user profile
router.get('/me', authenticateUser, async (req, res, next) => {
    try {
        logger.setContext({ userId: req.user.id, action: 'getProfile' });
        
        const user = await User.findById(req.user.id)
            .select('-password')
            .lean();

        if (!user) {
            logger.warning('User not found', { userId: req.user.id });
            throw new AppError('User not found', ERROR_TYPES.NOT_FOUND);
        }

        // Ensure picture is set
        if (!user.picture && user.email) {
            user.picture = `https://www.gravatar.com/avatar/${crypto.createHash('md5').update(user.email.toLowerCase().trim()).digest('hex')}?d=mp&s=200`;
            await User.findByIdAndUpdate(user._id, { picture: user.picture });
        }

        logger.success('Profile retrieved successfully', { userId: req.user.id });
        res.json({
            success: true,
            data: {
                user: {
                    id: user._id,
                    email: user.email,
                    name: user.name,
                    picture: user.picture,
                    role: user.role,
                    createdAt: user.createdAt,
                    updatedAt: user.updatedAt
                }
            }
        });
    } catch (error) {
        logger.error('Error fetching profile', { 
            userId: req.user.id,
            error: error.message 
        });
        next(error);
    } finally {
        logger.clearContext();
    }
});

// Update user profile
router.put('/me', authenticateUser, async (req, res, next) => {
    try {
        logger.setContext({ userId: req.user.id, action: 'updateProfile' });
        
        const { name, email, picture } = req.body;
        
        // Validate ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
            logger.warning('Invalid user ID format', { userId: req.user.id });
            throw new AppError('Invalid user ID format', ERROR_TYPES.VALIDATION_ERROR);
        }

        const user = await User.findById(req.user.id);
        
        if (!user) {
            logger.warning('User not found', { userId: req.user.id });
            throw new AppError('User not found', ERROR_TYPES.NOT_FOUND);
        }

        if (name) user.name = name;
        if (email) user.email = email;
        if (picture) user.picture = picture;

        await user.save();
        
        logger.success('Profile updated successfully', { userId: req.user.id });
        res.json({
            success: true,
            data: {
                user: {
                    id: user._id,
                    email: user.email,
                    name: user.name,
                    picture: user.picture,
                    role: user.role,
                    createdAt: user.createdAt,
                    updatedAt: user.updatedAt
                }
            }
        });
    } catch (error) {
        logger.error('Error updating profile', { 
            userId: req.user.id,
            error: error.message 
        });
        next(error);
    } finally {
        logger.clearContext();
    }
});

// Update user password
router.put('/me/password', authenticateUser, async (req, res, next) => {
    try {
        logger.setContext({ userId: req.user.id, action: 'updatePassword' });
        
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            logger.warning('Password update attempt with missing data');
            throw new AppError('Current password and new password are required', 400, ERROR_TYPES.VALIDATION);
        }

        // Validate ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
            logger.warning('Invalid user ID format', { userId: req.user.id });
            throw new AppError('Invalid user ID format', ERROR_TYPES.VALIDATION_ERROR);
        }

        const user = await User.findById(req.user.id).select('+password');
        
        if (!user) {
            logger.warning('User not found', { userId: req.user.id });
            throw new AppError('User not found', ERROR_TYPES.NOT_FOUND);
        }

        // Verify current password
        const isMatch = await user.comparePassword(currentPassword);
        if (!isMatch) {
            logger.warning('Invalid current password', { userId: req.user.id });
            throw new AppError('Current password is incorrect', 401, ERROR_TYPES.AUTHENTICATION);
        }

        // Update password
        user.password = newPassword;
        await user.save();
        
        logger.success('Password updated successfully', { userId: req.user.id });
        res.json({
            success: true,
            message: 'Password updated successfully'
        });
    } catch (error) {
        logger.error('Error updating password', { 
            userId: req.user.id,
            error: error.message 
        });
        next(error);
    } finally {
        logger.clearContext();
    }
});

// Delete user profile
router.delete('/me', authenticateUser, async (req, res, next) => {
    try {
        logger.setContext({ userId: req.user.id, action: 'deleteProfile' });
        
        // Validate ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
            logger.warning('Invalid user ID format', { userId: req.user.id });
            throw new AppError('Invalid user ID format', ERROR_TYPES.VALIDATION_ERROR);
        }

        const user = await User.findById(req.user.id);
        
        if (!user) {
            logger.warning('User not found', { userId: req.user.id });
            throw new AppError('User not found', ERROR_TYPES.NOT_FOUND);
        }

        await user.deleteOne();
        
        logger.success('Profile deleted successfully', { userId: req.user.id });
        res.json({
            success: true,
            message: 'User profile deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting profile', { 
            userId: req.user.id,
            error: error.message 
        });
        next(error);
    } finally {
        logger.clearContext();
    }
});

module.exports = router;