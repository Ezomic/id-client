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
"thijssensoftware/id-client": "^0.4.0"
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
| `access.revoked` | End the local session and dispatch `AccessRevoked`; the user lost access to this app |
| `user.updated` | Refresh the cached `name` and `email` |

A payload with no `event` is treated as a logout, which is what a pre-0.3 ID
server sends.

## Access revocation

`access.revoked` stamps `sso_logged_out_at` like a logout, which only ends the
web session. An app that issues anything else, such as Sanctum API tokens, keeps
accepting those after ID revokes the user's access unless it listens for
`Thijssensoftware\IdClient\Events\AccessRevoked`:

```php
use App\Models\User;
use Illuminate\Support\Facades\Event;
use LogicException;
use Thijssensoftware\IdClient\Events\AccessRevoked;

Event::listen(function (AccessRevoked $event): void {
    if (! $event->user instanceof User) {
        throw new LogicException('id-client.user_model is not '.User::class.'.');
    }

    $event->user->tokens()->delete();
});
```

The event is part of the package's contract, so its class name and its `user`
property only change in a new minor:

- `user` is the local user model (`id-client.user_model`), already carrying the
  `sso_logged_out_at` stamp. It is typed as `Model`, because the package only
  knows your class from config, so narrow it to your own model as above before
  calling anything that model adds, such as `tokens()`. Larastan rejects the
  call otherwise. Throw when it is not your model rather than returning: a
  misconfigured app then answers 500, which ID records and retries, instead of
  answering 200 and keeping every token.
- It is dispatched once per local user whose `idp_id` matches, on
  `access.revoked` only, and not at all when no local user matches.
- It is never dispatched on `logout`. ID sends that per session, so tying
  tokens to it would kill a script every time the user signs out on another
  machine.

Nothing listens by default. A listener runs inside ID's delivery, so keep it
quick and idempotent. ID waits five seconds for an answer and counts a timeout
or anything but a 2xx as a failure. It makes five attempts in all: the first
right after the revoke, then one on each of its retry runs, which come every
five minutes. After the fifth, at most about 20 minutes after the first, it
gives up for good. A queued listener gets none of those retries: the endpoint
answers 200 as soon as the job is queued, so ID never sees it fail. Give a
queued listener its own `$tries` and `$backoff`.

ID does not send `access.revoked` for every way a user can lose access yet, and
without it your listener never runs:

- A revoked grant reaches the app only if ID still holds a token issued to that
  user for it and an authorized-client row for them. Signing out at ID deletes
  both, and the token from the last sign-in is purged about a week later. So a
  user who signed in once, created an API token, and then signed out at ID or
  stayed away for a week gets no `access.revoked` when their access is revoked.
  Taking a user off the app's access list on ID's applications screen, rather
  than on the user's page or through a group, sends nothing at all. ID-89
  tracks sending it for every revoked grant.
- Deactivating the app at ID revokes its OAuth client and tokens and sends the
  app nothing, not even a `logout`. ID-89 does not change that.
- A user deleting their own ID account sends no `access.revoked`, at most a
  `logout` to the apps signed in from the session that deleted it, which ends
  the web session but does not dispatch `AccessRevoked`. ID-89 does not change
  that either.

Until ID sends it in all of these cases, do not treat this event alone as a
guarantee that a user who lost access loses what the app issued them.

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

### Upgrading from 0.3.x

Bump to `^0.4.0` and redeploy. No new environment variable and no migration.
It includes both 0.3.1 fixes below.

The only change is the `AccessRevoked` event. Nothing listens to it by default,
so an app behaves exactly as on 0.3 until it registers a listener. Any app that
issues its own credentials, such as API tokens, should register one: see
[Access revocation](#access-revocation).

### Upgrading from 0.3.0 to 0.3.1

Run `composer update thijssensoftware/id-client` in every app on `^0.3.0`. The
constraint stays as it is, and there is no new environment variable and no
migration. Two fixes to back-channel logout:

- In an app whose user model does not cast `sso_logged_out_at`, a user's first
  logout broke that app for them until it upgraded. The stamp stays on the user
  row, so every request from every later SSO sign-in answered 500, not only the
  rest of the session that was signed out. The middleware now parses the raw
  value itself, so no cast is needed, and an existing cast keeps working.
  (ID-87)
- A remember-me cookie outlived a logout. Sign-in always sets one, and a
  session restored from it never passed through the SSO callback, so it had no
  sign-in time for the middleware to compare the logout against. `logout` and
  `access.revoked` now also replace the user's `remember_token`, which stops
  the cookie restoring a session after the logout. The middleware now stamps a
  session the cookie restores with the time of the restore, so a logout that
  comes later ends it on its next request like any other session. A cookie the
  guard refuses (a user with no password, for one) leaves the session alone.
  (ID-88)

What the upgrade cannot reach backwards: a user who was signed out while the
app was still on 0.3.0 kept the `remember_token` that logout never replaced, so
their old cookie still restores a session after the upgrade, stamped with the
time of that restore and so newer than the logout. Sessions restored before the
upgrade also stay unstamped until they expire. Where that matters, replace
`remember_token` once for every user whose `sso_logged_out_at` is already set.

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
