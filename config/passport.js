const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const User = require('../models/User');

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
        emails: profile.emails,
        photos: profile.photos
      });

      let user = await User.findOne({ googleId: profile.id });
      
      if (!user) {
        const email = profile.emails?.[0]?.value;
        if (email) {
          user = await User.findOne({ email });
          if (user) {
            user.googleId = profile.id;
            user.name = profile.displayName;
            user.picture = profile.photos?.[0]?.value;
            user.lastLogin = new Date();
            await user.save();
          }
        }
      }
      
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
          picture: profile.photos[0].value,
          lastLogin: new Date()
        });
      } else {
        user.lastLogin = new Date();
        user.name = profile.displayName;
        user.picture = profile.photos?.[0]?.value;
        await user.save();
      }
      
      return done(null, user);
    } catch (error) {
      console.error('Google Strategy Error:', error);
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

      if (!profile.id) throw new Error('GitHub profile ID is missing');

      let user = await User.findOne({ githubId: profile.id });
      
      if (!user) {
        const email = profile.emails?.[0]?.value;
        if (email) {
          user = await User.findOne({ email });
          if (user) {
            user.githubId = profile.id;
            user.lastLogin = new Date();
            await user.save();
          }
        }
      }
      
      if (!user) {
        user = await User.create({
          githubId: profile.id,
          email: profile.emails?.[0]?.value || `${profile.id}@github.com`,
          name: profile.displayName || profile.username,
          picture: profile.photos?.[0]?.value,
          lastLogin: new Date()
        });
      } else {
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
