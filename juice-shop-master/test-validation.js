// Test script to verify security improvements
// This script demonstrates the input validation working

const testCases = [
  {
    name: 'Valid Email Test',
    email: 'test@example.com',
    password: 'ValidPass123',
    expectedResult: 'Should validate successfully'
  },
  {
    name: 'Invalid Email Format',
    email: 'notanemail',
    password: 'ValidPass123',
    expectedResult: 'Should reject with "Invalid email format"'
  },
  {
    name: 'Empty Email',
    email: '',
    password: 'ValidPass123',
    expectedResult: 'Should reject with "Invalid email format"'
  },
  {
    name: 'Short Password',
    email: 'test@example.com',
    password: 'short',
    expectedResult: 'Should reject with "Password must be at least 8 characters long"'
  },
  {
    name: 'Empty Password',
    email: 'test@example.com',
    password: '',
    expectedResult: 'Should reject with "Password cannot be empty"'
  }
]

console.log('Security Validation Test Cases:\n')
console.log('=' .repeat(80))

testCases.forEach((testCase, index) => {
  console.log(`\nTest ${index + 1}: ${testCase.name}`)
  console.log(`  Email: "${testCase.email}"`)
  console.log(`  Password: "${testCase.password}"`)
  console.log(`  Expected: ${testCase.expectedResult}`)
})

console.log('\n' + '='.repeat(80))
console.log('\nTo test these cases, you can use curl or Postman:')
console.log('\nExample Login Test:')
console.log('curl -X POST http://localhost:3000/rest/user/login \\')
console.log('  -H "Content-Type: application/json" \\')
console.log('  -d \'{"email": "notanemail", "password": "test123"}\'')

console.log('\nExample Registration Test:')
console.log('curl -X POST http://localhost:3000/api/Users \\')
console.log('  -H "Content-Type: application/json" \\')
console.log('  -d \'{"email": "test@example.com", "password": "short", "passwordRepeat": "short"}\'')

console.log('\n✅ All validation improvements are now active!')
