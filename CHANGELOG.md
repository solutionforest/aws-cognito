# Changelog

## v0.2.21 (Solution Forest fork)

- Raise the floor of `spomky-labs/pki-framework` (used by `web-token/jwt-library`) to ^1.2.2 and
  `fakerphp/faker` (dev) to ^1.24: older releases emit implicit-nullable deprecations on PHP 8.4/8.5,
  caught by the `prefer-lowest` CI jobs.

## v0.2.20 (Solution Forest fork)

- Require PHP ^8.2; tested on PHP 8.2, 8.3, 8.4 and 8.5.
- Replace the abandoned `web-token/jwt-signature` / `jwt-signature-algorithm-rsa` 2.x packages with
  `web-token/jwt-library` ^4.0 (same `Jose\Component\*` API). `ext-gmp` is no longer required.
- Fix PHP 8.3/8.4 deprecations: `get_class()` without arguments, implicitly nullable `$previous`
  parameters in `CognitoResponseException` and `PasswordResetRequiredException`.
- Tests rewritten on top of the AWS SDK `MockHandler` (PHPUnit 11/12) and new token verification
  tests; GitHub Actions matrix replaces Travis CI.
