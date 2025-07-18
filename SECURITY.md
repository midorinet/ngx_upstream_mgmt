# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this NGINX module, please report it responsibly:

1. **Do not** create a public GitHub issue for security vulnerabilities
2. Email security details to: [your-email@domain.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Considerations

### Access Control
- Always restrict access to the management API endpoints
- Use IP allowlists in your nginx configuration
- Consider implementing authentication/authorization

### Rate Limiting
- Implement rate limiting for API endpoints to prevent abuse
- Monitor for unusual API usage patterns

### Input Validation
- The module validates all input parameters
- JSON parsing is done safely with bounds checking
- URI parsing includes buffer overflow protection

### Network Security
- Use HTTPS in production environments
- Consider network segmentation for management interfaces

### Example Secure Configuration

```nginx
location /api/upstreams {
    upstream_mgmt;
    
    # Restrict access to management network
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;
    
    # Rate limiting
    limit_req zone=api burst=10 nodelay;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # Request size limits
    client_max_body_size 1k;
    client_body_buffer_size 1k;
}
```

## Security Features

- Input validation and sanitization
- Buffer overflow protection
- Rate limiting support
- Memory safety checks
- Bounds checking for all operations
- Secure JSON parsing