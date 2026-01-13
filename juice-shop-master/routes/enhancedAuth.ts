/*
 * Enhanced Login Route with JWT Authentication
 * Demonstrates secure token-based authentication
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import * as auth from '../lib/auth'
import * as models from '../models/index'
import validator from 'validator'

/**
 * Enhanced login endpoint with JWT token generation
 */
export function enhancedLogin() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body

      // Step 1: Input Validation
      if (!email || !password) {
        return res.status(400).json({
          error: 'Missing credentials',
          message: 'Email and password are required'
        })
      }

      // Validate email format
      if (!validator.isEmail(email)) {
        return res.status(400).json({
          error: 'Invalid email',
          message: 'Please provide a valid email address'
        })
      }

      // Step 2: Find user in database
      // Using parameterized query to prevent SQL injection
      const user = await UserModel.findOne({ 
        where: { 
          email: email.trim().toLowerCase()
        } 
      })

      if (!user) {
        return res.status(401).json({
          error: 'Invalid credentials',
          message: 'Email or password is incorrect'
        })
      }

      // Step 3: Verify password
      // Check if password matches (using legacy hash for compatibility)
      const hashedPassword = security.hash(password)
      
      if (user.password !== hashedPassword) {
        return res.status(401).json({
          error: 'Invalid credentials',
          message: 'Email or password is incorrect'
        })
      }

      // Step 4: Check if 2FA is enabled
      if (user.totpSecret && user.totpSecret !== '') {
        // User has 2FA enabled, return special response
        const tmpToken = auth.generateAccessToken(user.id, user.email, user.role)
        return res.status(200).json({
          status: 'totp_required',
          message: '2FA verification required',
          tmpToken
        })
      }

      // Step 5: Generate JWT tokens
      const tokens = auth.generateAuthTokens(user.id, user.email, user.role)

      // Step 6: Return success response with tokens
      res.status(200).json({
        success: true,
        message: 'Login successful',
        authentication: {
          token: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresIn: tokens.expiresIn,
          tokenType: 'Bearer'
        },
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role
        }
      })

    } catch (error) {
      console.error('Login error:', error)
      next(error)
    }
  }
}

/**
 * Token refresh endpoint
 */
export function refreshToken() {
  return async (req: Request, res: Response) => {
    try {
      const { refreshToken } = req.body

      if (!refreshToken) {
        return res.status(400).json({
          error: 'Missing refresh token',
          message: 'Refresh token is required'
        })
      }

      // Verify refresh token
      const payload = auth.verifyRefreshToken(refreshToken)

      if (!payload) {
        return res.status(403).json({
          error: 'Invalid refresh token',
          message: 'Refresh token is invalid or expired'
        })
      }

      // Fetch user from database
      const user = await UserModel.findByPk(payload.userId)

      if (!user) {
        return res.status(404).json({
          error: 'User not found',
          message: 'User associated with this token no longer exists'
        })
      }

      // Generate new access token
      const accessToken = auth.generateAccessToken(user.id, user.email, user.role)

      res.status(200).json({
        success: true,
        accessToken,
        expiresIn: 3600,
        tokenType: 'Bearer'
      })

    } catch (error) {
      console.error('Token refresh error:', error)
      res.status(500).json({
        error: 'Server error',
        message: 'Failed to refresh token'
      })
    }
  }
}

/**
 * Logout endpoint (client-side token deletion)
 */
export function logout() {
  return (req: Request, res: Response) => {
    // With JWT, logout is primarily handled client-side by deleting the token
    // Here we can implement token blacklisting if needed
    
    res.status(200).json({
      success: true,
      message: 'Logged out successfully. Please delete your tokens.'
    })
  }
}

/**
 * Get current user profile (protected route example)
 */
export function getCurrentUser() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.authenticatedUser) {
        return res.status(401).json({
          error: 'Not authenticated',
          message: 'Please log in to access this resource'
        })
      }

      const user = await UserModel.findByPk(req.authenticatedUser.userId)

      if (!user) {
        return res.status(404).json({
          error: 'User not found',
          message: 'User account not found'
        })
      }

      res.status(200).json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role,
          profileImage: user.profileImage
        }
      })

    } catch (error) {
      console.error('Get user error:', error)
      next(error)
    }
  }
}
