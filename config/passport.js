const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const User = require('../models/User');
const axios = require('axios');

// Helper function to convert image URL to base64
async function convertImageToBase64(imageUrl) {
  try {
    const response = await axios.get(imageUrl, { responseType: 'arraybuffer' });
    const base64 = Buffer.from(response.data, 'binary').toString('base64');
    const mimeType = response.headers['content-type'];
    return `data:${mimeType};base64,${base64}`;
  } catch (error) {
    console.error('Error converting image to base64:', error);
    return null;
  }
}

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/api/auth/google/callback",
    scope: ['profile', 'email']
  },
  async function(accessToken, refreshToken, profile, done) {
    try {
      console.log('Google authentication successful');
      console.log('Profile:', {
        id: profile.id,
        displayName: profile.displayName,
        email: profile.emails[0].value
      });

      // Convert Google profile picture to base64
      let picture = null;
      if (profile.photos && profile.photos[0]) {
        picture = await convertImageToBase64(profile.photos[0].value);
      }

      // Find or create user
      let user = await User.findOne({ email: profile.emails[0].value });
      
      if (!user) {
        user = await User.create({
          email: profile.emails[0].value,
          name: profile.displayName,
          picture: picture,
          isVerified: true, // Google accounts are pre-verified
          authProvider: 'google',
          googleId: profile.id
        });
      } else {
        // Update existing user's Google info
        user.googleId = profile.id;
        user.authProvider = 'google';
        if (picture) {
          user.picture = picture;
        }
        await user.save();
      }

      return done(null, user);
    } catch (error) {
      console.error('Error in Google authentication:', error);
      return done(error, null);
    }
  }
));

// GitHub Strategy
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/api/auth/github/callback",
    scope: ['user:email']
  },
  async function(accessToken, refreshToken, profile, done) {
    try {
      console.log('GitHub authentication successful');
      console.log('Access Token:', accessToken ? 'Present' : 'Missing');
      console.log('Profile:', {
        id: profile.id,
        username: profile.username,
        displayName: profile.displayName,
        emails: profile.emails,
        photos: profile.photos
      });

      if (!profile.id) {
        throw new Error('GitHub profile ID is missing');
      }

      // First try to find user by GitHub ID
      let user = await User.findOne({ githubId: profile.id });
      
      if (!user) {
        // If not found by GitHub ID, try to find by email
        const email = profile.emails?.[0]?.value;
        if (email) {
          user = await User.findOne({ email });
          if (user) {
            // Update existing user with GitHub ID
            console.log('Updating existing user with GitHub ID:', user._id);
            user.githubId = profile.id;
            user.lastLogin = new Date();
            await user.save();
          }
        }
      }
      
      if (!user) {
        // Create new user if doesn't exist
        console.log('Creating new user for GitHub ID:', profile.id);
        user = await User.create({
          githubId: profile.id,
          email: profile.emails?.[0]?.value || `${profile.id}@github.com`,
          name: profile.displayName || profile.username,
          picture: profile.photos?.[0]?.value,
          lastLogin: new Date()
        });
        console.log('New user created:', user._id);
      } else {
        console.log('Updating existing user:', user._id);
        // Update last login
        user.lastLogin = new Date();
        await user.save();
      }
      
      return done(null, user);
    } catch (error) {
      console.error('GitHub Strategy Error:', error);
      return done(error, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

module.exports = passport; 