describe('Security Tests', () => {
  test('passwords are properly hashed', async () => {
    const password = 'TestPassword123!'
    const hashedPassword = await hashPassword(password)
    expect(hashedPassword).not.toBe(password)
    expect(hashedPassword).toMatch(/^\$2[ayb]\$.{56}$/) // bcrypt format
  })

  test('XSS prevention works', () => {
    const input = '<script>alert("xss")</script>'
    const sanitized = sanitizeInput(input)
    expect(sanitized).not.toContain('<script>')
  })

  test('SQL injection prevention works', () => {
    const input = "'; DROP TABLE users; --"
    const query = buildQuery(input)
    expect(query).toContain('?') // Parameterized query
    expect(query).not.toContain(input)
  })
})
