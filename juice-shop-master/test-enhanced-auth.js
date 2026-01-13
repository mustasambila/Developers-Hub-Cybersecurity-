// Enhanced Authentication Test Script
// Demonstrates JWT-based authentication with access and refresh tokens

console.log('===============================================')
console.log('Enhanced JWT Authentication Test Guide')
console.log('===============================================\n')

console.log('The enhanced authentication system includes:\n')
console.log('✅ Access tokens (1 hour expiry)')
console.log('✅ Refresh tokens (7 days expiry)')
console.log('✅ Role-based access control')
console.log('✅ Token validation middleware')
console.log('✅ Secure password verification\n')

console.log('===============================================')
console.log('1. LOGIN (Get Access & Refresh Tokens)')
console.log('===============================================\n')

console.log('Endpoint: POST /api/auth/login')
console.log('Content-Type: application/json\n')

console.log('Request Body:')
console.log(JSON.stringify({
  email: 'admin@juice-sh.op',
  password: 'admin123'
}, null, 2))

console.log('\nExpected Success Response:')
console.log(JSON.stringify({
  success: true,
  message: 'Login successful',
  authentication: {
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    expiresIn: 3600,
    tokenType: 'Bearer'
  },
  user: {
    id: 1,
    email: 'admin@juice-sh.op',
    username: 'admin',
    role: 'admin'
  }
}, null, 2))

console.log('\n\nCURL Command:')
console.log(`curl -X POST http://localhost:3000/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"admin@juice-sh.op","password":"admin123"}'`)

console.log('\n\n===============================================')
console.log('2. ACCESS PROTECTED ROUTE (Get Current User)')
console.log('===============================================\n')

console.log('Endpoint: GET /api/auth/me')
console.log('Authorization: Bearer <access_token>\n')

console.log('Expected Success Response:')
console.log(JSON.stringify({
  success: true,
  user: {
    id: 1,
    email: 'admin@juice-sh.op',
    username: 'admin',
    role: 'admin',
    profileImage: '/assets/public/images/uploads/defaultAdmin.png'
  }
}, null, 2))

console.log('\n\nCURL Command:')
console.log(`curl -X GET http://localhost:3000/api/auth/me \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"`)

console.log('\n\nExpected Error (No Token):')
console.log(JSON.stringify({
  error: 'Access token required',
  message: 'No authentication token provided'
}, null, 2))

console.log('\n\n===============================================')
console.log('3. REFRESH TOKEN (Get New Access Token)')
console.log('===============================================\n')

console.log('Endpoint: POST /api/auth/refresh')
console.log('Content-Type: application/json\n')

console.log('Request Body:')
console.log(JSON.stringify({
  refreshToken: 'your-refresh-token-here'
}, null, 2))

console.log('\nExpected Success Response:')
console.log(JSON.stringify({
  success: true,
  accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  expiresIn: 3600,
  tokenType: 'Bearer'
}, null, 2))

console.log('\n\nCURL Command:')
console.log(`curl -X POST http://localhost:3000/api/auth/refresh \\
  -H "Content-Type: application/json" \\
  -d '{"refreshToken":"YOUR_REFRESH_TOKEN"}'`)

console.log('\n\n===============================================')
console.log('4. LOGOUT (Client-side Token Deletion)')
console.log('===============================================\n')

console.log('Endpoint: POST /api/auth/logout')
console.log('\nExpected Response:')
console.log(JSON.stringify({
  success: true,
  message: 'Logged out successfully. Please delete your tokens.'
}, null, 2))

console.log('\n\nCURL Command:')
console.log(`curl -X POST http://localhost:3000/api/auth/logout`)

console.log('\n\n===============================================')
console.log('5. ERROR SCENARIOS')
console.log('===============================================\n')

console.log('Invalid Email Format:')
console.log(JSON.stringify({
  error: 'Invalid email',
  message: 'Please provide a valid email address'
}, null, 2))

console.log('\nInvalid Credentials:')
console.log(JSON.stringify({
  error: 'Invalid credentials',
  message: 'Email or password is incorrect'
}, null, 2))

console.log('\nExpired Token:')
console.log(JSON.stringify({
  error: 'Invalid token',
  message: 'Token is invalid or expired'
}, null, 2))

console.log('\n\n===============================================')
console.log('TESTING WORKFLOW')
console.log('===============================================\n')

console.log('Step 1: Login and save the access token and refresh token')
console.log('Step 2: Use access token to call protected endpoints')
console.log('Step 3: When access token expires (1 hour), use refresh token')
console.log('Step 4: Get new access token and continue')
console.log('Step 5: Logout when done (delete tokens client-side)\n')

console.log('===============================================')
console.log('TOKEN STRUCTURE')
console.log('===============================================\n')

console.log('Access Token Payload:')
console.log(JSON.stringify({
  userId: 1,
  email: 'admin@juice-sh.op',
  role: 'admin',
  iat: 1673524800,
  exp: 1673528400
}, null, 2))

console.log('\nRefresh Token Payload:')
console.log(JSON.stringify({
  userId: 1,
  iat: 1673524800,
  exp: 1674129600
}, null, 2))

console.log('\n\n===============================================')
console.log('SECURITY FEATURES')
console.log('===============================================\n')

console.log('✅ JWT tokens with HMAC SHA-256 signature')
console.log('✅ Access tokens expire after 1 hour')
console.log('✅ Refresh tokens expire after 7 days')
console.log('✅ Email format validation')
console.log('✅ Password verification')
console.log('✅ Role-based access control')
console.log('✅ Bearer token authentication')
console.log('✅ Secure error messages (no information leakage)\n')

console.log('===============================================')
console.log('POSTMAN COLLECTION EXAMPLE')
console.log('===============================================\n')

const postmanCollection = {
  info: {
    name: 'Juice Shop Enhanced Auth',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
  },
  item: [
    {
      name: 'Login',
      request: {
        method: 'POST',
        url: 'http://localhost:3000/api/auth/login',
        header: [
          { key: 'Content-Type', value: 'application/json' }
        ],
        body: {
          mode: 'raw',
          raw: JSON.stringify({
            email: 'admin@juice-sh.op',
            password: 'admin123'
          })
        }
      }
    },
    {
      name: 'Get Current User',
      request: {
        method: 'GET',
        url: 'http://localhost:3000/api/auth/me',
        header: [
          { key: 'Authorization', value: 'Bearer {{access_token}}' }
        ]
      }
    }
  ]
}

console.log('Import this JSON into Postman:')
console.log(JSON.stringify(postmanCollection, null, 2))

console.log('\n\n✅ Enhanced authentication system is ready!')
console.log('Start testing with the commands above.\n')
