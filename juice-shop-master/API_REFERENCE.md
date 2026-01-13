# Enhanced Authentication API Reference

## Quick Start Guide

### Base URL
```
http://localhost:3000
```

---

## Authentication Endpoints

### 1. Login
**POST** `/api/auth/login`

**Request:**
```json
{
  "email": "admin@juice-sh.op",
  "password": "admin123"
}
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "authentication": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600,
    "tokenType": "Bearer"
  },
  "user": {
    "id": 1,
    "email": "admin@juice-sh.op",
    "username": "admin",
    "role": "admin"
  }
}
```

**Error Responses:**
- `400` - Invalid email format
- `401` - Invalid credentials

---

### 2. Get Current User (Protected)
**GET** `/api/auth/me`

**Headers:**
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

**Success Response (200):**
```json
{
  "success": true,
  "user": {
    "id": 1,
    "email": "admin@juice-sh.op",
    "username": "admin",
    "role": "admin",
    "profileImage": "/assets/public/images/uploads/defaultAdmin.png"
  }
}
```

**Error Responses:**
- `401` - No token provided
- `403` - Invalid or expired token

---

### 3. Refresh Token
**POST** `/api/auth/refresh`

**Request:**
```json
{
  "refreshToken": "your-refresh-token-here"
}
```

**Success Response (200):**
```json
{
  "success": true,
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 3600,
  "tokenType": "Bearer"
}
```

**Error Responses:**
- `401` - No refresh token provided
- `403` - Invalid or expired refresh token

---

### 4. Logout
**POST** `/api/auth/logout`

**Success Response (200):**
```json
{
  "success": true,
  "message": "Logged out successfully. Please delete your tokens."
}
```

---

## Test Users

| Email | Password | Role |
|-------|----------|------|
| admin@juice-sh.op | admin123 | admin |
| jim@juice-sh.op | ncc-1701 | customer |
| bender@juice-sh.op | OhG0dPlease1nsertLiquor! | customer |

---

## cURL Examples

### Login
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}'
```

### Get Current User
```bash
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh Token
```bash
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"YOUR_REFRESH_TOKEN"}'
```

### Logout
```bash
curl -X POST http://localhost:3000/api/auth/logout
```

---

## JavaScript/Fetch Examples

### Login
```javascript
const login = async (email, password) => {
  const response = await fetch('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email, password })
  })
  
  const data = await response.json()
  
  if (data.success) {
    localStorage.setItem('accessToken', data.authentication.token)
    localStorage.setItem('refreshToken', data.authentication.refreshToken)
  }
  
  return data
}
```

### Get Current User
```javascript
const getCurrentUser = async () => {
  const token = localStorage.getItem('accessToken')
  
  const response = await fetch('http://localhost:3000/api/auth/me', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })
  
  return await response.json()
}
```

### Refresh Token
```javascript
const refreshAccessToken = async () => {
  const refreshToken = localStorage.getItem('refreshToken')
  
  const response = await fetch('http://localhost:3000/api/auth/refresh', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ refreshToken })
  })
  
  const data = await response.json()
  
  if (data.success) {
    localStorage.setItem('accessToken', data.accessToken)
  }
  
  return data
}
```

---

## Token Information

### Access Token
- **Expiry:** 1 hour
- **Algorithm:** HS256
- **Usage:** Include in Authorization header for protected endpoints

### Refresh Token
- **Expiry:** 7 days
- **Algorithm:** HS256
- **Usage:** Get new access token when current one expires

### Token Payload Structure
```json
{
  "userId": 1,
  "email": "admin@juice-sh.op",
  "role": "admin",
  "iat": 1673524800,
  "exp": 1673528400
}
```

---

## Error Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request (invalid input) |
| 401 | Unauthorized (no token or invalid credentials) |
| 403 | Forbidden (invalid or expired token) |
| 404 | Not Found (user doesn't exist) |
| 500 | Internal Server Error |

---

## Security Best Practices

1. **Store Tokens Securely**
   - Use httpOnly cookies (preferred)
   - Or localStorage with XSS protection

2. **Handle Token Expiration**
   - Implement automatic token refresh
   - Redirect to login on refresh failure

3. **Clear Tokens on Logout**
   - Remove from storage
   - Clear from memory

4. **HTTPS in Production**
   - Never send tokens over HTTP
   - Use secure cookies

5. **Validate on Every Request**
   - Don't trust client-side token validation
   - Always validate server-side

---

## Integration Checklist

- [ ] Implement login form
- [ ] Store tokens securely
- [ ] Add Authorization header to protected requests
- [ ] Handle token expiration (401/403 responses)
- [ ] Implement automatic token refresh
- [ ] Add logout functionality
- [ ] Clear tokens on logout
- [ ] Test with different user roles

---

## Support

For questions or issues:
- Review the full documentation: `SECURITY_IMPLEMENTATION_GUIDE.md`
- Test using: `node test-enhanced-auth.js`
- Check server logs for detailed error messages

---

**API Version:** 2.0  
**Last Updated:** January 12, 2026
