# About

This is used to validate `Cf-Access-Jwt-Assertion` JWTs from cloudflare. ([details](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/))

The reson for this binary is that `cloudflared` will validate JWTs for all path, but we actually only want this for `/admin`.

# Usage

Env vars need:

```
TEAM_NAME=<your-team-name>
POLICY_AUD=<https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/#get-your-aud-tag>
```
