import userModel from "./models/user.model.js";
import config from "./config/config.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import sessionModel from "./models/session.model.js";
import { sendEmail } from "./services/email.services.js";
import { generateOTP, getOTPHtml } from "./utils/utils.js";
import otpModel from "./models/otp.model.js";

/**
- @concept REGISTER USER + SEND OTP
- @route POST /api/auth/register
*/
export async function registerUser(req, res) {
	try {
		const { username, email, password } = req.body;

		// [VALIDATION STEP] Ensure structural properties exist cleanly
		if (!username || !email || !password) {
			return res.status(400).json({ message: 'All fields are required' });
		}

		// Check availability
		const existingUser = await userModel.findOne({ $or: [{ username }, { email }] });
		if (existingUser) {
			return res.status(409).json({ message: 'Username or email already exists' });
		}

		// Security: Secure password hashing before persistence
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(password, salt);

		// Persist new inactive user document
		const newUser = await userModel.create({
			username,
			email,
			password: hashedPassword,
		});

		// [OTP WORKFLOW START]
		const otp = generateOTP();
		const html = getOTPHtml(otp);
		const otpHash = await bcrypt.hash(otp, 10); // Hash token for database safety

		// Store secure trace lookup
		await otpModel.create({
			email,
			user: newUser._id,
			otpHash
		});

		// Dispatch out via Gmail OAuth2 Transporter
		await sendEmail(email, 'Verify your email', `Your OTP is: ${otp}`, html);
		return res.status(201).json({
			message: 'User registered successfully. Please verify your email.',
			userId: newUser._id,
			verified: newUser.verified
		});
	} catch (error) {
		console.error('Error registering user:', error);
		return res.status(500).json({ message: 'Internal server error' });
	}
}

/**
- @concept VERIFY EMAIL via JSON Request Body (No dynamic URL query pollution)
- @route POST /api/auth/verify-email
*/
export async function verifyEmail(req, res) {
	try {
		const { email, otp } = req.body;

		if (!email || !otp) {
			return res.status(400).json({ message: 'Email and OTP are required' });
		}

		// 1. Fetch record by unique identifying email index
		const otpRecord = await otpModel.findOne({ email });
		if (!otpRecord) {
			return res.status(400).json({ message: 'Invalid or expired verification token' });
		}

		// 2. Cryptographically match payload against hashed DB record
		const isOtpValid = await bcrypt.compare(otp, otpRecord.otpHash);
		if (!isOtpValid) {
			return res.status(400).json({ message: 'Invalid or expired verification token' });
		}

		// 3. Complete user state mutation [02:41:59]
		await userModel.findByIdAndUpdate(otpRecord.user, { verified: true });

		// 4. Clean up database document securely
		await otpModel.findByIdAndDelete(otpRecord._id);

		return res.status(200).json({ message: 'Email verified successfully' });
	} catch (error) {
		console.error('Error verifying email:', error);
		return res.status(500).json({ message: 'Internal server error' });
	}
}

/**
- @concept LOGIN USER + JWT Token Strategy + Stateful Sessions [02:42:12]
- @route POST /api/auth/login
*/
export async function login(req, res) {
	try {
		const { email, password } = req.body;

		if (!email || !password) {
			return res.status(400).json({ message: 'Email and password are required' });
		}

		const user = await userModel.findOne({ email });
		if (!user) {
			return res.status(401).json({ message: 'Invalid credentials' });
		}

		// [VERIFICATION GUARD] Block unverified accounts from access tokens [02:42:17]
		if (!user.verified) {
			return res.status(403).json({ message: 'Email not verified. Please verify your email before logging in.' });
		}

		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) {
			return res.status(401).json({ message: 'Invalid credentials' });
		}

		// Create a trace tracking session in MongoDB (Enables revoke tracking)
		const newSession = await sessionModel.create({
			user: user._id,
			refreshToken: 'Staged', // Temporary placeholder before hashing rotation link
			ip: req.ip,
			userAgent: req.headers['user-agent'],
		});

		// Long-lived payload creation
		const refreshToken = jwt.sign(
			{ userId: user._id, sessionId: newSession._id },
			config.JWT_SECRET,
			{ expiresIn: '7d' }
		);

		// Hash refresh token state in DB for advanced security baseline
		const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
		await sessionModel.findByIdAndUpdate(newSession._id, { refreshToken: hashedRefreshToken });

		// Short-lived ephemeral access token creation
		const accessToken = jwt.sign(
			{ userId: user._id, sessionId: newSession._id },
			config.JWT_SECRET,
			{ expiresIn: '15m' }
		);

		// Safe cookie delivery pipeline
		res.cookie('refreshToken', refreshToken, {
			httpOnly: true, // Safeguards against cross-site scripting (XSS)
			secure: true,   // Transmits over encrypted HTTPS contexts only
			sameSite: 'strict',
			maxAge: 7 * 24 * 60 * 60 * 1000,
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
- @concept RECOVER LOGGED-IN IDENTITY PROFILE
- @route GET /api/auth/get-me
*/
export async function getMe(req, res) {
	try {
		// Priority Fallback routing for credentials validation
		const token = req.cookies.refreshToken || req.headers.authorization?.split(' ')[1];
		if (!token) {
			return res.status(401).json({ message: 'Unauthorized' });
		}

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
- @concept CYCLE AND RE-AUTH SHORT-LIVED ACCESS TOKENS
- @route GET /api/auth/refresh-token
*/
export async function refreshToken(req, res) {
	try {
		const refreshTokenCookie = req.cookies.refreshToken;
		if (!refreshTokenCookie) {
			return res.status(401).json({ message: 'Unauthorized' });
		}

		const decoded = jwt.verify(refreshTokenCookie, config.JWT_SECRET);

		// Session validation interceptor check
		const session = await sessionModel.findOne({ _id: decoded.sessionId, revoked: false });
		if (!session) {
			return res.status(401).json({ message: 'Unauthorized session context' });
		}

		// Refresh token rotation (RTR) setup for high security integrity
		const newRefreshToken = jwt.sign(
			{ userId: decoded.userId, sessionId: session._id },
			config.JWT_SECRET,
			{ expiresIn: '7d' }
		);

		const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 10);
		await sessionModel.findByIdAndUpdate(session._id, { refreshToken: newRefreshTokenHash });

		const accessToken = jwt.sign(
			{ userId: decoded.userId, sessionId: session._id },
			config.JWT_SECRET,
			{ expiresIn: '15m' }
		);

		res.cookie('refreshToken', newRefreshToken, {
			httpOnly: true,
			secure: true,
			sameSite: 'strict',
			maxAge: 7 * 24 * 60 * 60 * 1000,
		});

		return res.status(200).json({ accessToken });
	} catch (error) {
		console.error('Error refreshing token:', error);
		return res.status(500).json({ message: 'Internal server error' });
	}
}

/**
- @concept LOGOUT SINGLE ACTIVE CHANNEL
- @route POST /api/auth/logout
*/
export async function logout(req, res) {
	try {
		const refreshTokenCookie = req.cookies.refreshToken;
		if (!refreshTokenCookie) {
			return res.status(400).json({ message: 'Refresh token is required' });
		}

		const decoded = jwt.verify(refreshTokenCookie, config.JWT_SECRET);

		// Revoke singular device footprint safely
		await sessionModel.findByIdAndUpdate(decoded.sessionId, { revoked: true });
		res.clearCookie('refreshToken');

		return res.status(200).json({ message: 'User logged out successfully' });
	} catch (error) {
		console.error('Error logging out user:', error);
		return res.status(500).json({ message: 'Internal server error' });
	}
}

/**
- @concept KILL FLOATING LOGINS ACROSS EVERY KNOWN AGENT
- @route POST /api/auth/logout-all
*/
export async function logoutAll(req, res) {
	try {
		const token = req.cookies.refreshToken || req.headers.authorization?.split(' ')[1];
		if (!token) {
			return res.status(401).json({ message: 'Unauthorized' });
		}

		const decoded = jwt.verify(token, config.JWT_SECRET);

		// Database Bulk Operation: Kill permission states matching owner parameter
		await sessionModel.updateMany(
			{ user: decoded.userId, revoked: false },
			{ revoked: true }
		);

		res.clearCookie('refreshToken');
		return res.status(200).json({ message: 'Logged out from all devices successfully' });
	} catch (error) {
		console.error('Error logging out from all devices:', error);
		return res.status(500).json({ message: 'Internal server error' });
	}
}