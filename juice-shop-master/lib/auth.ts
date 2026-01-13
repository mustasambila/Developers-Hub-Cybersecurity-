/*
 * Enhanced JWT Authentication Module
 * Provides secure token-based authentication with refresh tokens
 */

import jwt from 'jsonwebtoken'
import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'

// Secret keys - In production, these should be in environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret-key-change-in-production'
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key-change-in-production'

// Token expiration times
const ACCESS_TOKEN_EXPIRY = '1h'  // Access token valid for 1 hour
const REFRESH_TOKEN_EXPIRY = '7d' // Refresh token valid for 7 days

// Interface for JWT payload
interface JWTPayload {
  userId: number
  email: string
  role: string
  iat?: number
  exp?: number
}

// Interface for token response
interface TokenResponse {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

/**
 * Generate access token
 * @param userId - User's unique ID
 * @param email - User's email
 * @param role - User's role (customer, admin, etc.)
 * @returns JWT access token
 */
export const generateAccessToken = (userId: number, email: string, role: string = 'customer'): string => {
  const payload: JWTPayload = {
    userId,
    email,
    role
  }
  
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
    algorithm: 'HS256'
  })
}

/**
 * Generate refresh token
 * @param userId - User's unique ID
 * @returns JWT refresh token
 */
export const generateRefreshToken = (userId: number): string => {
  return jwt.sign({ userId }, JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRY,
    algorithm: 'HS256'
  })
}

/**
 * Generate both access and refresh tokens
 * @param userId - User's unique ID
 * @param email - User's email
 * @param role - User's role
 * @returns Object containing both tokens
 */
export const generateAuthTokens = (userId: number, email: string, role: string = 'customer'): TokenResponse => {
  const accessToken = generateAccessToken(userId, email, role)
  const refreshToken = generateRefreshToken(userId)
  
  return {
    accessToken,
    refreshToken,
    expiresIn: 3600 // 1 hour in seconds
  }
}

/**
 * Verify access token
 * @param token - JWT token to verify
 * @returns Decoded payload or null if invalid
 */
export const verifyAccessToken = (token: string): JWTPayload | null => {
  try {
    return jwt.verify(token, JWT_SECRET) as JWTPayload
  } catch (error) {
    return null
  }
}

/**
 * Verify refresh token
 * @param token - Refresh token to verify
 * @returns Decoded payload or null if invalid
 */
export const verifyRefreshToken = (token: string): { userId: number } | null => {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET) as { userId: number }
  } catch (error) {
    return null
  }
}

/**
 * Middleware to authenticate requests using JWT
 * Checks Authorization header for Bearer token
 */
export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1] // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ 
      error: 'Access token required',
      message: 'No authentication token provided'
    })
  }

  const payload = verifyAccessToken(token)
  
  if (!payload) {
    return res.status(403).json({ 
      error: 'Invalid token',
      message: 'Token is invalid or expired'
    })
  }

  // Attach user info to request
  req.authenticatedUser = payload
  next()
}

/**
 * Middleware to check if user has required role
 * @param allowedRoles - Array of allowed roles
 */
export const requireRole = (...allowedRoles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.authenticatedUser) {
      return res.status(401).json({ 
        error: 'Authentication required',
        message: 'You must be logged in to access this resource'
      })
    }

    const userRole = req.authenticatedUser.role
    
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        message: `This resource requires one of the following roles: ${allowedRoles.join(', ')}`
      })
    }

    next()
  }
}

/**
 * Refresh access token using refresh token
 */
export const refreshAccessToken = (req: Request, res: Response) => {
  const { refreshToken } = req.body

  if (!refreshToken) {
    return res.status(401).json({ 
      error: 'Refresh token required',
      message: 'No refresh token provided'
    })
  }

  const payload = verifyRefreshToken(refreshToken)
  
  if (!payload) {
    return res.status(403).json({ 
      error: 'Invalid refresh token',
      message: 'Refresh token is invalid or expired'
    })
  }

  // In production, fetch user details from database using payload.userId
  // For now, we'll generate a new access token
  const accessToken = generateAccessToken(payload.userId, '', 'customer')
  
  res.json({ 
    accessToken,
    expiresIn: 3600
  })
}

/**
 * Extract token from request
 * Supports Authorization header and query parameter
 */
export const extractToken = (req: Request): string | null => {
  // Check Authorization header
  const authHeader = req.headers['authorization']
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }

  // Check query parameter
  if (req.query.token && typeof req.query.token === 'string') {
    return req.query.token
  }

  // Check cookies
  if (req.cookies && req.cookies.token) {
    return req.cookies.token
  }

  return null
}

// Extend Express Request type to include user
declare module 'express-serve-static-core' {
  interface Request {
    authenticatedUser?: JWTPayload
  }
}

export default {
  generateAccessToken,
  generateRefreshToken,
  generateAuthTokens,
  verifyAccessToken,
  verifyRefreshToken,
  authenticateToken,
  requireRole,
  refreshAccessToken,
  extractToken
}
