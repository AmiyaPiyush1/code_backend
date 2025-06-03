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
                    bio: user.bio,
                    role: user.role,
                    isVerified: user.isVerified,
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
        
        const { name, email, picture, bio } = req.body;
        
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

        // Store the current isVerified status
        const currentIsVerified = user.isVerified;

        if (name) user.name = name;
        if (email) user.email = email;
        if (picture) user.picture = picture;
        if (bio !== undefined) user.bio = bio;

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
                    bio: user.bio,
                    role: user.role,
                    isVerified: currentIsVerified, // Preserve the verification status
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

// Change email route
router.post('/change-email', authenticateUser, async (req, res, next) => {
    try {
        logger.setContext({ userId: req.user.id, action: 'changeEmail' });
        
        const { newEmail, password } = req.body;
        
        if (!newEmail || !password) {
            throw new AppError('New email and password are required', ERROR_TYPES.VALIDATION);
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(newEmail)) {
            throw new AppError('Invalid email format', ERROR_TYPES.VALIDATION);
        }

        // Check if email is already in use
        const existingUser = await User.findOne({ email: newEmail.toLowerCase().trim() });
        if (existingUser) {
            throw new AppError('Email is already in use', ERROR_TYPES.VALIDATION);
        }

        const user = await User.findById(req.user.id).select('+password');
        
        if (!user) {
            throw new AppError('User not found', ERROR_TYPES.NOT_FOUND);
        }

        // Verify current password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            throw new AppError('Invalid password', ERROR_TYPES.VALIDATION);
        }

        // Generate verification token
        const verificationToken = user.generateVerificationToken();
        
        // Update email and set as unverified
        user.email = newEmail.toLowerCase().trim();
        user.isVerified = false;
        await user.save();

        // Send verification email
        await sendVerificationEmail(user.email, verificationToken);
        
        logger.success('Email change initiated', { userId: req.user.id, newEmail: user.email });
        res.json({
            success: true,
            message: 'Email change initiated. Please verify your new email address.'
        });
    } catch (error) {
        logger.error('Error changing email', { 
            userId: req.user.id,
            error: error.message 
        });
        next(error);
    } finally {
        logger.clearContext();
    }
});

// Check email availability
router.post('/check-email', async (req, res, next) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            throw new AppError('Email is required', ERROR_TYPES.VALIDATION);
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            throw new AppError('Invalid email format', ERROR_TYPES.VALIDATION);
        }

        // Check if email is already in use
        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        
        res.json({
            success: true,
            available: !existingUser
        });
    } catch (error) {
        next(error);
    }
});

// Update profile picture
router.post('/update-profile', authenticateUser, async (req, res) => {
  try {
    const { picture } = req.body;
    const userId = req.user.id;

    // Validate picture data
    if (picture) {
      // Check if it's a valid base64 image
      if (!picture.startsWith('data:image/')) {
        return res.status(400).json({
          success: false,
          message: 'Invalid image format. Please upload a valid image.'
        });
      }

      // Check base64 string length (max 5MB)
      const base64Data = picture.split(',')[1];
      const maxSize = 5 * 1024 * 1024; // 5MB
      const sizeInBytes = Math.ceil((base64Data.length * 3) / 4);
      
      if (sizeInBytes > maxSize) {
        return res.status(400).json({
          success: false,
          message: 'Image size should be less than 5MB'
        });
      }

      // Validate image format
      const imageFormat = picture.split(';')[0].split('/')[1];
      const validFormats = ['jpeg', 'png', 'webp'];
      if (!validFormats.includes(imageFormat)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid image format. Please upload a JPEG, PNG, or WebP image.'
        });
      }
    }

    // Update user profile
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { picture },
      { new: true, runValidators: true }
    ).select('-password -refreshToken');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Log the profile update
    logger.info(`User profile updated: ${updatedUser.email}`, {
      userId: updatedUser._id,
      action: 'update_profile',
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: updatedUser
      }
    });
  } catch (error) {
    logger.error('Error updating profile:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile',
      error: error.message
    });
  }
});

module.exports = router;