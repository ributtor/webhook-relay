# webhook-relay

Receive, log, and forward webhooks with retry and verification.

## Features
- Receive webhooks on configurable endpoints
- Forward to multiple targets
- Retry with exponential backoff
- HMAC signature verification
- Request logging and replay

## Usage
```bash
# Start relay
webhook-relay --port 9000 --forward https://target.example.com/hook

# With signature verification
webhook-relay --port 9000 --secret mysecret --forward https://target.com
```

## License
MIT
