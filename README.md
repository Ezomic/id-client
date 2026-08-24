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
| `POST /auth/sso/logout` | Back-channel events, called by ID |

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

## Versioning

The package is versioned `0.x` and consumers pin an explicit caret on the minor:

```json
"thijssensoftware/id-client": "^0.2.0"
```

A caret on a `0.x` version is locked to that minor, so a bump is a deliberate,
per-app edit rather than something `composer update` picks up on its own. That is
intentional: 0.2 needs a new environment variable and a migration, so a consumer
that pulled it silently would break rather than upgrade. Treat a minor bump as a
coordinated rollout across the estate, not a dependency refresh.

## Back-channel events

`POST /auth/sso/logout` carries an `event` field. From 0.3 on, unknown types are
ignored with a 200, so upgrading ID never breaks a consumer on 0.3 or later.

0.2 is a different story: it does not read the field at all and ends the session
on any signed payload it accepts, so an event that does not mean "sign out" logs
the user out anyway. ID protects itself against that rather than trusting the
version: it probes each consumer with an unknown event, treats the `ignored`
answer as the only proof of 0.3, and withholds anything but a sign-out from
consumers that answer otherwise. See ID-77.

| Event | Effect |
|-------|--------|
| `logout` | End the local session |
| `access.revoked` | End the local session; the user lost access to this app |
| `user.updated` | Refresh the cached `name` and `email` |

A payload with no `event` is treated as a logout, which is what a pre-0.3 ID
server sends.

## Signing out of the whole estate

`EstateLogout::perform()` ends this app's session and asks ID to end the rest.
Plain local logout stays available and unchanged; which one you offer is your
decision.

```php
use Thijssensoftware\IdClient\EstateLogout;

Route::post('/logout', function () {
    EstateLogout::perform();

    return redirect('/');
});
```

The request is authenticated with the user's own access token, so an app can
only end the session of the person whose token it holds.

### Upgrading from 0.2.x

Bump to `^0.3.0` and redeploy. No new environment variable and no migration.

Worth doing rather than deferring: a 0.2 consumer does not merely miss the newer
events, it mishandles them. It ends the session on anything signed, so a profile
update reads as a sign-out. ID withholds those events until it has probed the
consumer and seen 0.3 answer, which means an app left on 0.2 keeps working but
never receives them.

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
