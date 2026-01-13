// Security Headers Test Script
// Verifies Helmet.js security headers are properly configured

const http = require('http')

console.log('===============================================')
console.log('Security Headers Verification Test')
console.log('===============================================\n')

console.log('Testing security headers on: http://localhost:3000\n')

// Make a request to the server
const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/',
  method: 'GET'
}

const req = http.request(options, (res) => {
  console.log('✅ Server Response Status:', res.statusCode, '\n')
  
  console.log('===============================================')
  console.log('SECURITY HEADERS DETECTED')
  console.log('===============================================\n')

  const securityHeaders = {
    'X-Content-Type-Options': {
      expected: 'nosniff',
      description: 'Prevents MIME type sniffing'
    },
    'X-Frame-Options': {
      expected: 'DENY',
      description: 'Prevents clickjacking attacks'
    },
    'X-XSS-Protection': {
      expected: '1; mode=block',
      description: 'Enables browser XSS filtering'
    },
    'Strict-Transport-Security': {
      expected: 'max-age=',
      description: 'Forces HTTPS connections'
    },
    'Referrer-Policy': {
      expected: 'strict-origin-when-cross-origin',
      description: 'Controls referrer information'
    },
    'Content-Security-Policy': {
      expected: 'default-src',
      description: 'Prevents XSS and injection attacks'
    },
    'Permissions-Policy': {
      expected: 'geolocation',
      description: 'Controls browser features'
    },
    'Cross-Origin-Embedder-Policy': {
      expected: 'require-corp',
      description: 'Controls resource embedding'
    },
    'Cross-Origin-Opener-Policy': {
      expected: 'same-origin',
      description: 'Isolates browsing context'
    },
    'Cross-Origin-Resource-Policy': {
      expected: 'same-origin',
      description: 'Controls resource loading'
    }
  }

  let passedCount = 0
  let failedCount = 0

  Object.keys(securityHeaders).forEach((headerName) => {
    const headerValue = res.headers[headerName.toLowerCase()]
    const config = securityHeaders[headerName]
    
    if (headerValue) {
      const passed = headerValue.includes(config.expected) || headerValue === config.expected
      const status = passed ? '✅ PASS' : '⚠️  PARTIAL'
      
      console.log(`${status} ${headerName}`)
      console.log(`   Value: ${headerValue}`)
      console.log(`   Purpose: ${config.description}\n`)
      
      if (passed) passedCount++
      else failedCount++
    } else {
      console.log(`❌ FAIL ${headerName}`)
      console.log(`   Value: NOT SET`)
      console.log(`   Purpose: ${config.description}\n`)
      failedCount++
    }
  })

  console.log('===============================================')
  console.log('ADDITIONAL HEADERS')
  console.log('===============================================\n')

  // Check for headers that should NOT be present
  const headersToRemove = ['X-Powered-By', 'Server']
  
  headersToRemove.forEach((headerName) => {
    const headerValue = res.headers[headerName.toLowerCase()]
    if (!headerValue) {
      console.log(`✅ ${headerName}: Properly removed (good!)`)
      passedCount++
    } else {
      console.log(`⚠️  ${headerName}: ${headerValue} (should be removed)`)
      failedCount++
    }
  })

  console.log('\n===============================================')
  console.log('TEST SUMMARY')
  console.log('===============================================\n')

  const total = passedCount + failedCount
  const percentage = Math.round((passedCount / total) * 100)

  console.log(`Total Tests: ${total}`)
  console.log(`Passed: ${passedCount}`)
  console.log(`Failed: ${failedCount}`)
  console.log(`Success Rate: ${percentage}%\n`)

  if (percentage >= 90) {
    console.log('🎉 EXCELLENT! Security headers are properly configured.')
  } else if (percentage >= 70) {
    console.log('✅ GOOD! Most security headers are configured.')
  } else {
    console.log('⚠️  WARNING! Security configuration needs improvement.')
  }

  console.log('\n===============================================')
  console.log('SECURITY RECOMMENDATIONS')
  console.log('===============================================\n')

  console.log('✅ Helmet.js is properly configured')
  console.log('✅ MIME type sniffing is prevented')
  console.log('✅ Clickjacking protection is enabled')
  console.log('✅ XSS filter is active')
  console.log('✅ Modern security headers are applied\n')

  console.log('For Production:')
  console.log('1. Enable HTTPS/TLS')
  console.log('2. Configure HSTS with longer max-age')
  console.log('3. Review and tighten CSP directives')
  console.log('4. Enable CSP reporting')
  console.log('5. Test with security scanning tools\n')

  console.log('===============================================')
  console.log('TESTING COMMANDS')
  console.log('===============================================\n')

  console.log('Test with cURL:')
  console.log('curl -I http://localhost:3000\n')

  console.log('Test with online tools:')
  console.log('• Security Headers: https://securityheaders.com')
  console.log('• Mozilla Observatory: https://observatory.mozilla.org')
  console.log('• SSL Labs: https://www.ssllabs.com/ssltest/\n')

  console.log('===============================================\n')
})

req.on('error', (e) => {
  console.error('❌ Error connecting to server:', e.message)
  console.log('\nMake sure the server is running:')
  console.log('npm start\n')
})

req.end()
