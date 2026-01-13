/*
 * Enhanced Security Configuration with Helmet.js
 * Provides comprehensive HTTP security headers
 */

import helmet from 'helmet'

/**
 * Enhanced Helmet Configuration
 * Implements industry-standard security headers
 */
export const enhancedHelmetConfig = {
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'", // Required for some inline scripts
        "'unsafe-eval'", // Required for Angular
        'https://code.getmdl.io',
        'https://ajax.googleapis.com'
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://fonts.googleapis.com',
        'https://code.getmdl.io'
      ],
      fontSrc: [
        "'self'",
        'https://fonts.gstatic.com',
        'data:'
      ],
      imgSrc: [
        "'self'",
        'data:',
        'https:',
        'http:'
      ],
      connectSrc: ["'self'"],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },

  // Strict Transport Security (HSTS)
  hsts: {
    maxAge: 31536000, // 1 year in seconds
    includeSubDomains: true,
    preload: true
  },

  // Prevent MIME type sniffing
  noSniff: true,

  // X-Frame-Options
  frameguard: {
    action: 'deny' // Prevent clickjacking
  },

  // X-XSS-Protection (legacy but still useful)
  xssFilter: true,

  // Referrer Policy
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  },

  // Remove X-Powered-By header
  hidePoweredBy: true,

  // DNS Prefetch Control
  dnsPrefetchControl: {
    allow: false
  },

  // Expect-CT
  expectCt: {
    enforce: true,
    maxAge: 86400 // 1 day
  },

  // Permissions Policy (formerly Feature Policy)
  permittedCrossDomainPolicies: {
    permittedPolicies: 'none'
  }
}

/**
 * Production-ready Helmet Configuration
 * More strict settings for production environment
 */
export const productionHelmetConfig = {
  ...enhancedHelmetConfig,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      fontSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: {
    maxAge: 63072000, // 2 years
    includeSubDomains: true,
    preload: true
  }
}

/**
 * Development Helmet Configuration
 * Relaxed settings for development
 */
export const developmentHelmetConfig = {
  contentSecurityPolicy: false, // Disabled for easier development
  hsts: false, // No HSTS in development
  noSniff: true,
  frameguard: { action: 'sameorigin' },
  xssFilter: true,
  referrerPolicy: { policy: 'no-referrer-when-downgrade' }
}

/**
 * Get appropriate helmet configuration based on environment
 */
export const getHelmetConfig = () => {
  const env = process.env.NODE_ENV || 'development'
  
  switch (env) {
    case 'production':
      return productionHelmetConfig
    case 'development':
      return developmentHelmetConfig
    default:
      return enhancedHelmetConfig
  }
}

/**
 * Security headers explanation
 */
export const securityHeadersInfo = {
  'Content-Security-Policy': 'Prevents XSS attacks by controlling resource loading',
  'Strict-Transport-Security': 'Forces HTTPS connections',
  'X-Content-Type-Options': 'Prevents MIME type sniffing',
  'X-Frame-Options': 'Prevents clickjacking attacks',
  'X-XSS-Protection': 'Enables browser XSS filtering',
  'Referrer-Policy': 'Controls referrer information',
  'Permissions-Policy': 'Controls browser features and APIs',
  'Expect-CT': 'Enforces Certificate Transparency'
}

export default {
  enhancedHelmetConfig,
  productionHelmetConfig,
  developmentHelmetConfig,
  getHelmetConfig,
  securityHeadersInfo
}
