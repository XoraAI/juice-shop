# Required before merging

- **Generate a new RSA key pair (2048-bit minimum).** The committed 1024-bit key is
  publicly known and must never be reused. Example:
  ```
  openssl genrsa -out jwt_private.pem 2048
  openssl rsa -in jwt_private.pem -pubout -RSAPublicKey_out -out jwt.pub
  ```

- **Set environment variable `RSA_PRIVATE_KEY`** in every environment (production,
  staging, CI) to the PEM-encoded content of the newly generated private key
  (including the `-----BEGIN RSA PRIVATE KEY-----` / `-----END RSA PRIVATE KEY-----`
  header and footer, with `\n` line endings). Without this variable the server will
  fail to sign JWTs on startup. Store the value in your secrets manager (AWS Secrets
  Manager, HashiCorp Vault, GitHub Actions secret, etc.) — never in source code or
  plaintext config files.

- **Replace `encryptionkeys/jwt.pub`** with the matching public key produced by the
  step above. This file is served publicly and must correspond to the new private key.

- **Revoke the leaked key.** The original 1024-bit private key
  (`MIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxx…`) is
  permanently compromised. Rotating the key (steps above) invalidates all existing
  user sessions — inform users if appropriate.

- **Rotate the `deluxeToken` HMAC secret.** `deluxeToken()` in `lib/insecurity.ts`
  uses `privateKey` as its HMAC-SHA256 secret. After key rotation, all previously
  issued deluxe tokens are automatically invalidated because the secret changes; no
  additional action is needed beyond the `RSA_PRIVATE_KEY` rotation above.

- **Restrict the `/encryptionkeys` route** (optional hardening). The directory
  listing and public-key file are intentionally served as part of this application's
  challenge design, but in a real deployment this directory should not be publicly
  browseable.
