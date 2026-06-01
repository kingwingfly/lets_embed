# About

This is used to validate `Cf-Access-Jwt-Assertion` JWTs from cloudflare. ([details](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/))

# Usage

Env vars need:

```
TEAM_NAME=<your-team-name>
POLICY_AUD=<https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/#get-your-aud-tag>
```

# Reasons not to use this:

- cloudflare worker can do everything, including jwt verification, load balance and rate limiting...
- only cloudflare's access control (service auth) can protect resources on CDN, local pingora proxy cannot
- `cloudflared` can validate all jwts, you can turn on this: `Enforce Access JSON Web Token (JWT) validation
`
