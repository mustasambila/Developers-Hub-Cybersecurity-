# Security Headers Quick Reference

## Helmet.js Implementation Summary

### What is Helmet.js?

Helmet.js is a collection of middleware functions that set HTTP security headers to protect Express applications from common web vulnerabilities.

---

## Security Headers Implemented

### 1. Content-Security-Policy (CSP)
**Purpose:** Prevents XSS and code injection attacks

**Configuration:**
```javascript
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```

**Protection:**
- Controls which resources can be loaded
- Blocks malicious scripts
- Prevents data injection

---

### 2. Strict-Transport-Security (HSTS)
**Purpose:** Forces HTTPS connections

**Configuration:**
```javascript
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Protection:**
- Prevents protocol downgrade attacks
- Protects against cookie hijacking
- Ensures encrypted connections

---

### 3. X-Content-Type-Options
**Purpose:** Prevents MIME type sniffing

**Configuration:**
```javascript
X-Content-Type-Options: nosniff
```

**Protection:**
- Prevents browsers from MIME-sniffing
- Blocks malicious file type detection
- Reduces attack surface

---

### 4. X-Frame-Options
**Purpose:** Prevents clickjacking

**Configuration:**
```javascript
X-Frame-Options: DENY
```

**Protection:**
- Prevents UI redress attacks
- Blocks iframe embedding
- Protects against clickjacking

---

### 5. X-XSS-Protection
**Purpose:** Enables browser XSS filter

**Configuration:**
```javascript
X-XSS-Protection: 1; mode=block
```

**Protection:**
- Activates browser XSS filtering
- Blocks page rendering on XSS detection
- Legacy but still useful protection

---

### 6. Referrer-Policy
**Purpose:** Controls referrer information

**Configuration:**
```javascript
Referrer-Policy: strict-origin-when-cross-origin
```

**Protection:**
- Prevents information leakage
- Controls what referrer data is sent
- Protects user privacy

---

### 7. Permissions-Policy
**Purpose:** Restricts browser features

**Configuration:**
```javascript
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Protection:**
- Disables unnecessary features
- Prevents unauthorized access
- Reduces attack vectors

---

### 8. Cross-Origin Policies
**Purpose:** Isolates resources

**Configuration:**
```javascript
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

**Protection:**
- Prevents cross-origin attacks
- Isolates browsing contexts
- Protects sensitive data

---

## Implementation Steps

### Step 1: Install Helmet.js
```bash
npm install helmet
```

### Step 2: Import in Your Application
```javascript
import helmet from 'helmet'
```

### Step 3: Apply Basic Configuration
```javascript
app.use(helmet())
```

### Step 4: Customize Configuration
```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true
  }
}))
```

---

## Testing Your Headers

### Using cURL
```bash
# View all headers
curl -I http://localhost:3000

# View specific header
curl -I http://localhost:3000 | grep "X-Frame-Options"
```

### Using Browser DevTools
1. Open DevTools (F12)
2. Go to Network tab
3. Refresh page
4. Click on request
5. View Response Headers

### Using Online Tools
- **Security Headers:** https://securityheaders.com
- **Mozilla Observatory:** https://observatory.mozilla.org
- **Report URI:** https://report-uri.com/home/tools

---

## Common Issues and Solutions

### Issue 1: CSP Blocking Resources
**Problem:** Content Security Policy blocking legitimate resources

**Solution:** Add trusted sources to CSP directives
```javascript
scriptSrc: ["'self'", 'https://trusted-cdn.com']
```

### Issue 2: X-Frame-Options Too Strict
**Problem:** Need to allow framing from same origin

**Solution:** Use SAMEORIGIN instead of DENY
```javascript
frameguard: { action: 'sameorigin' }
```

### Issue 3: HSTS in Development
**Problem:** HTTPS not available in local development

**Solution:** Disable HSTS in development
```javascript
const helmetConfig = process.env.NODE_ENV === 'production'
  ? { hsts: { maxAge: 31536000 } }
  : { hsts: false }
```

---

## Best Practices

### ✅ DO
- Enable all security headers
- Use HTTPS in production
- Test headers before deployment
- Monitor CSP violations
- Keep Helmet.js updated
- Document your configuration

### ❌ DON'T
- Disable security headers without reason
- Use unsafe-inline in CSP unless necessary
- Ignore CSP violation reports
- Skip testing after changes
- Hardcode secrets in configuration

---

## Security Checklist

- [ ] Helmet.js installed
- [ ] Basic configuration applied
- [ ] CSP directives customized
- [ ] HSTS enabled (production)
- [ ] X-Frame-Options set
- [ ] X-Content-Type-Options set
- [ ] Referrer-Policy configured
- [ ] Permissions-Policy applied
- [ ] X-Powered-By removed
- [ ] Tested with online tools
- [ ] Verified in browser
- [ ] Documented configuration

---

## Quick Commands

```bash
# Check all security headers
curl -I http://localhost:3000 | grep -E "X-|Content-Security|Strict-Transport"

# Test specific header
curl -I http://localhost:3000 | grep "X-Frame-Options"

# Save headers to file
curl -I http://localhost:3000 > headers.txt

# Compare before/after
diff old-headers.txt new-headers.txt
```

---

## Security Ratings

### Grade A+ Requirements
- ✅ Content-Security-Policy
- ✅ Strict-Transport-Security
- ✅ X-Content-Type-Options
- ✅ X-Frame-Options
- ✅ Referrer-Policy

### Additional Points
- ✅ Permissions-Policy
- ✅ Cross-Origin policies
- ✅ No vulnerable headers
- ✅ HTTPS enabled

---

## Further Reading

- [Helmet.js Documentation](https://helmetjs.github.io/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---

**Version:** 1.0  
**Last Updated:** January 12, 2026  
**Status:** Active ✅
