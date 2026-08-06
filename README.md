# thijssensoftware/id-client

Signs a workflow app in against [Thijssensoftware ID](https://id.thijssensoftware.nl),
the estate's OAuth2 identity provider (Laravel Passport, authorization_code + PKCE).

Installing the package is enough: it registers a Socialite driver, the SSO routes,
the back-channel logout endpoint, and the middleware that enforces single logout.

## Configuration

Register the app on the ID server, which prints everything below:

```bash
php artisan id:app "Billr" billr https://billr.thijssensoftware.nl/auth/sso/callback
```

```dotenv
THIJSSENSOFTWARE_ID_URL=https://id.thijssensoftware.nl
THIJSSENSOFTWARE_ID_CLIENT_ID=...
THIJSSENSOFTWARE_ID_CLIENT_SECRET=...
THIJSSENSOFTWARE_ID_LOGOUT_SECRET=...
```

Optional: `THIJSSENSOFTWARE_ID_GUARD`, `THIJSSENSOFTWARE_ID_USER_MODEL`,
`THIJSSENSOFTWARE_ID_HOME`, `THIJSSENSOFTWARE_ID_REDIRECT`,
`THIJSSENSOFTWARE_ID_PROVISION`.

## Routes

| Route | What it does |
|-------|--------------|
| `GET /auth/sso/redirect` | Starts the OAuth flow |
| `GET /auth/sso/callback` | Completes it and signs the user in |
| `POST /auth/sso/logout` | Back-channel logout, called by ID |

## Single logout

Signing out at ID used to leave every consumer app signed in, because each one
holds its own session and never asks ID anything after the callback.

ID now POSTs to `/auth/sso/logout` when a user signs out, signed with
`THIJSSENSOFTWARE_ID_LOGOUT_SECRET` (HMAC-SHA256 over the raw body, in the
`X-Id-Signature` header). The call carries no session cookie, so it stamps
`users.sso_logged_out_at`; `EnsureSsoSessionIsActive`, appended to the `web`
middleware group, turns that into a sign-out on the user's next request. That
works on any session driver.

Calls older than five minutes are rejected, so a captured request cannot be
replayed later.

### Upgrading from 0.1.x

Every consumer needs a redeploy for single logout to work:

1. `composer require thijssensoftware/id-client:^0.2`
2. Add `THIJSSENSOFTWARE_ID_LOGOUT_SECRET` to `.env`. Get it from
   `php artisan id:app --rotate <slug>` on the ID server, which also issues a
   new OAuth client secret, so update `THIJSSENSOFTWARE_ID_CLIENT_SECRET` at the
   same time.
3. `php artisan migrate` for `users.sso_logged_out_at`.

Until a consumer is redeployed its logout endpoint returns `501` and ID keeps
retrying on its schedule. The user's tokens are revoked at logout regardless, so
that app cannot refresh, but its existing local session survives until the
redeploy lands.

## Tests

```bash
composer test
```
