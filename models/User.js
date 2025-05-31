const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const validator = require("validator");

const UserSchema = new mongoose.Schema({
    email: { 
        type: String, 
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        validate: {
            validator: validator.isEmail,
            message: 'Please provide a valid email'
        }
    },
    password: { 
        type: String,
        select: false, // Hide password by default
        minlength: [8, 'Password must be at least 8 characters long'],
        validate: {
            validator: function(value) {
                // More user-friendly password validation
                const hasUpperCase = /[A-Z]/.test(value);
                const hasLowerCase = /[a-z]/.test(value);
                const hasNumbers = /\d/.test(value);
                const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(value);
                
                if (!hasUpperCase) {
                    this.invalidate('password', 'Password must contain at least one uppercase letter');
                }
                if (!hasLowerCase) {
                    this.invalidate('password', 'Password must contain at least one lowercase letter');
                }
                if (!hasNumbers) {
                    this.invalidate('password', 'Password must contain at least one number');
                }
                if (!hasSpecialChar) {
                    this.invalidate('password', 'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)');
                }
                
                return hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
            }
        }
    },
    name: { 
        type: String,
        trim: true,
        minlength: [2, 'Name must be at least 2 characters long'],
        maxlength: [50, 'Name cannot exceed 50 characters'],
        validate: {
            validator: function(value) {
                if (!value) return true; // Allow empty names
                // More lenient name validation
                return /^[a-zA-Z0-9\s\-'\.]*$/.test(value); // Allow letters, numbers, spaces, hyphens, apostrophes, and periods
            },
            message: 'Name can only contain letters, numbers, spaces, hyphens, apostrophes, and periods'
        }
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'moderator'],
        default: 'user'
    },
    googleId: { 
        type: String, 
        unique: true, 
        sparse: true,
        select: false
    },
    githubId: { 
        type: String, 
        unique: true, 
        sparse: true,
        select: false
    },
    picture: { 
        type: String,
        validate: {
            validator: function(value) {
                if (!value) return true; // Allow empty picture
                return validator.isURL(value);
            },
            message: 'Invalid profile picture URL'
        }
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: {
        type: String,
        select: false
    },
    verificationTokenExpiry: {
        type: Date,
        select: false
    },
    resetToken: { 
        type: String,
        select: false
    },
    resetTokenExpiry: { 
        type: Date,
        select: false
    },
    loginCount: {
        type: Number,
        default: 0
    },
    lastLogin: { 
        type: Date, 
        default: Date.now 
    },
    lastPasswordChange: {
        type: Date,
        default: Date.now
    },
    failedLoginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date
    },
    status: {
        type: String,
        enum: ['active', 'inactive', 'suspended', 'banned'],
        default: 'active'
    },
    preferences: {
        theme: {
            type: String,
            enum: ['light', 'dark', 'system'],
            default: 'system'
        },
        notifications: {
            email: {
                type: Boolean,
                default: true
            },
            push: {
                type: Boolean,
                default: true
            }
        },
        language: {
            type: String,
            default: 'en'
        }
    },
    createdAt: { 
        type: Date, 
        default: Date.now,
        immutable: true
    },
    updatedAt: { 
        type: Date, 
        default: Date.now 
    },
    // 2FA fields
    twoFactorSecret: {
        type: String,
        default: null
    },
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    recoveryCodes: [{
        type: String,
        select: false
    }],
    last2FAUsed: {
        type: Date
    },
    backupMethods: [{
        type: {
            type: String,
            enum: ['phone', 'email', 'authenticator'],
            required: true
        },
        value: {
            type: String,
            required: true
        },
        verified: {
            type: Boolean,
            default: false
        },
        addedAt: {
            type: Date,
            default: Date.now
        }
    }],
    twoFactorSettings: {
        rememberDevice: {
            type: Boolean,
            default: false
        },
        rememberDeviceDuration: {
            type: Number,
            default: 30 // days
        },
        trustedDevices: [{
            deviceId: String,
            deviceName: String,
            lastUsed: Date,
            expiresAt: Date
        }]
    },
    activeSessions: [{
        id: String,
        deviceInfo: {
            browser: String,
            os: String,
            ip: String
        },
        lastActive: Date,
        createdAt: {
            type: Date,
            default: Date.now
        }
    }]
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Indexes
UserSchema.index({ createdAt: -1 });
UserSchema.index({ status: 1 });
UserSchema.index({ role: 1 });

// Virtual for account age
UserSchema.virtual('accountAge').get(function() {
    return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Pre-save middleware
UserSchema.pre('save', async function(next) {
    try {
        // Handle email
        if (this.isModified('email')) {
            this.email = this.email.toLowerCase().trim();
        }

        // Handle password
        if (this.isModified('password')) {
            // Check if password is being changed
            if (this.password) {
                const salt = await bcrypt.genSalt(12);
                this.password = await bcrypt.hash(this.password, salt);
                this.lastPasswordChange = Date.now();
            }
        }

        // Set updatedAt
        this.updatedAt = Date.now();

        next();
    } catch (error) {
        next(error);
    }
});

// Instance methods
UserSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw new Error('Password comparison failed');
    }
};

UserSchema.methods.generateVerificationToken = function() {
    const token = crypto.randomBytes(32).toString('hex');
    this.verificationToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
    this.verificationTokenExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    return token;
};

UserSchema.methods.generatePasswordResetToken = function() {
    const token = crypto.randomBytes(32).toString('hex');
    this.resetToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
    this.resetTokenExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes
    return token;
};

UserSchema.methods.incrementLoginAttempts = async function() {
    if (this.lockUntil && this.lockUntil > Date.now()) {
        return;
    }
    
    this.failedLoginAttempts += 1;
    
    if (this.failedLoginAttempts >= 5) {
        this.lockUntil = Date.now() + 2 * 60 * 60 * 1000; // 2 hours
    }
    
    await this.save();
};

UserSchema.methods.resetLoginAttempts = async function() {
    this.failedLoginAttempts = 0;
    this.lockUntil = undefined;
    await this.save();
};

// Method to verify 2FA code
UserSchema.methods.verify2FACode = function(code) {
    const speakeasy = require('speakeasy');
    return speakeasy.totp.verify({
        secret: this.twoFactorSecret,
        encoding: 'base32',
        token: code,
        window: 1 // Allow 30 seconds clock skew
    });
};

// Method to verify recovery code
UserSchema.methods.verifyRecoveryCode = function(code) {
    const crypto = require('crypto');
    const hashedCode = crypto.createHash('sha256').update(code).digest('hex');
    const index = this.recoveryCodes.indexOf(hashedCode);
    
    if (index > -1) {
        // Remove used recovery code
        this.recoveryCodes.splice(index, 1);
        return true;
    }
    return false;
};

// Static methods
UserSchema.statics.handleDuplicateKeyError = function(error) {
    if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        return {
            error: `An account with this ${field} already exists`,
            suggestion: field === 'email' ? 'Please try logging in instead or use a different email address' : 'Please use a different value'
        };
    }
    return error;
};

// Query middleware
UserSchema.pre(/^find/, function(next) {
    this.find({ status: { $ne: 'banned' } });
    next();
});

const User = mongoose.model("User", UserSchema);

module.exports = User;