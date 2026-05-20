import userModel from "../models/user.model.js";
import config from "../config/config.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import sessionModel from "../models/session.model.js";
import { sendEmail } from "../services/email.services.js";
import { generateOTP,getOTPHtml } from "../utils/utils.js";
import otpModel from "../models/otp.model.js";
/**
 * Register a new user
 * @route POST /api/auth/register
 */
export async function registerUser(req, res) {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await userModel.findOne({
      $or: [{ username }, { email }],
    });
    if (existingUser) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = await userModel.create({
      username,
      email,
      password: hashedPassword,
    });
    //sedning mail to verify email address
    const otp = generateOTP();
    const html = getOTPHtml(otp);
    const otpHash = await bcrypt.hash(otp, 10);
    await otpModel.create({
        email,
        user:newUser._id,
        otpHash
    })
    await sendEmail(email, 'Verify your email', `Your OTP is: ${otp}`, html);
   

    return res.status(201).json({
      message: 'User registered successfully',
      userId: newUser._id,
      verified: newUser.verified
    });
  } catch (error) {
    console.error('Error registering user:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
} 

/**
 * Login user
 * @route POST /api/auth/login
 */
export async function login(req, res) {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Find user by email
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    // Check if email is verified
    if(!user.verified){
        return res.status(403).json({ message: 'Email not verified. Please verify your email before logging in.' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Create JWT Refresh token
    const refreshToken = jwt.sign(
      { userId: user._id },
      config.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Hash refresh token before storing in database for security
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    // Create session in database
    const sessionToken = await sessionModel.create({
      user: user._id,
      refreshToken: hashedRefreshToken,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Create JWT Access token
    const accessToken = jwt.sign(
      {
        userId: user._id,
        sessionId: sessionToken._id,
      },
      config.JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Set refresh token in httpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      message: 'User logged in successfully',
      userId: user._id,
      accessToken,
    });
  } catch (error) {
    console.error('Error logging in user:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

/**
 * Get current user
 * @route GET /api/auth/get-me
 */
export async function getMe(req, res) { // <--- Added missing export keyword
  try {
    // Fixed: Looking for 'refreshToken' cookie instead of 'token' to match registerUser
    const token = req.cookies.refreshToken || req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Verify token
    const decoded = jwt.verify(token, config.JWT_SECRET);
    const user = await userModel.findById(decoded.userId);

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({
      message: 'User fetched successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

/**
 * Refresh access token using refresh token
 * @route GET /api/auth/refresh-token
 */
export async function refreshToken(req, res) {
  try {
    const refreshTokenCookie = req.cookies.refreshToken;
    if (!refreshTokenCookie) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshTokenCookie, config.JWT_SECRET);

    // Check if session exists and is not revoked
    const session = await sessionModel.findOne({
      user: decoded.userId,
      revoked: false,
    });

    if (!session) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Create new access token
    const accessToken = jwt.sign(
      { userId: decoded.userId },
      config.JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Rotate refresh token for added security
    const newRefreshToken = jwt.sign(
      { userId: decoded.userId },
      config.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 10);

    // Update session with new refresh token
    await sessionModel.findByIdAndUpdate(session._id, {
      refreshToken: newRefreshTokenHash,
    });

    // Set new refresh token in httpOnly cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({ accessToken });
  } catch (error) {
    console.error('Error refreshing token:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

/**
 * Logout user
 * @route POST /api/auth/logout
 */
export async function logout(req, res) {
  try {
    const refreshTokenCookie = req.cookies.refreshToken;
    if (!refreshTokenCookie) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshTokenCookie, config.JWT_SECRET);

    // Find session
    const session = await sessionModel.findOne({
      user: decoded.userId,
      revoked: false,
    });

    if (!session) {
      return res.status(400).json({ message: 'Invalid refresh token' });
    }

    // Revoke session
    await sessionModel.findByIdAndUpdate(session._id, { revoked: true });

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    return res.status(200).json({ message: 'User logged out successfully' });
  } catch (error) {
    console.error('Error logging out user:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

/**
 * logout from all devices (revoke all sessions)
 * @route POST /api/auth/logout-all
 */

export async function logoutAll(req, res) {
  try{
    const token = req.cookies.refreshToken || req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    //if token found
    const decoded = jwt.verify(token, config.JWT_SECRET);

    // Revoke all sessions for the user
    await sessionModel.updateMany(
      { user: decoded.userId, revoked: false },
      { revoked: true }
    );
    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    return res.status(200).json({ message: 'Logged out from all devices successfully' });
  }catch(error){
    console.error('Error logging out from all devices:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

export async function verifyEmail(req, res) {
    try {
        // 1. Read from the JSON request body (req.body) 
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ message: 'Email and OTP are required' });
        }

        // 2. Find the OTP document using the user's email address
        const otpRecord = await otpModel.findOne({ email });
        if (!otpRecord) {
            return res.status(400).json({ message: 'Invalid or expired verification token' });
        }

        // 3. Compare the incoming plain-text OTP with the hashed OTP in MongoDB
        const isOtpValid = await bcrypt.compare(otp, otpRecord.otpHash);
        if (!isOtpValid) {
            return res.status(400).json({ message: 'Invalid or expired verification token' });
        }

        // 4. Update user verified status to true
        await userModel.findByIdAndUpdate(otpRecord.user, { verified: true });

        // 5. Safely clean up and delete the single OTP document (Fixed the "findByIdAndDeleteMany" typo)
        await otpModel.findByIdAndDelete(otpRecord._id);

        return res.status(200).json({ message: 'Email verified successfully' });
    }
    catch (error) {
        console.error('Error verifying email:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}