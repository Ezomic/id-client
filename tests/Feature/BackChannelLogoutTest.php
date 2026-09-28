<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Thijssensoftware\IdClient\Http\Middleware\EnsureSsoSessionIsActive;
use Thijssensoftware\IdClient\Tests\Fixtures\User;
use Thijssensoftware\IdClient\Tests\Fixtures\UserWithoutRememberToken;

const LOGOUT_SECRET = 'shared-logout-secret';

function signedCall(array $payload, ?string $secret = LOGOUT_SECRET)
{
    $body = json_encode($payload, JSON_THROW_ON_ERROR);

    return test()->call(
        'POST',
        '/auth/sso/logout',
        server: [
            'HTTP_X_ID_SIGNATURE' => hash_hmac('sha256', $body, $secret ?? ''),
            'CONTENT_TYPE' => 'application/json',
        ],
        content: $body,
    );
}

beforeEach(function () {
    config()->set('id-client.logout_secret', LOGOUT_SECRET);
});

it('marks the user signed out on a correctly signed call', function () {
    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    signedCall(['sub' => '42', 'issued_at' => Carbon::now()->getTimestamp(), 'nonce' => 'abc'])
        ->assertOk()
        ->assertJson(['status' => 'ok']);

    expect($user->fresh()->sso_logged_out_at)->not->toBeNull();
});

it('rejects a call signed with the wrong secret', function () {
    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    signedCall(['sub' => '42', 'issued_at' => Carbon::now()->getTimestamp()], 'not-the-secret')
        ->assertUnauthorized();

    expect($user->fresh()->sso_logged_out_at)->toBeNull();
});

it('rejects an unsigned call', function () {
    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    test()->postJson('/auth/sso/logout', ['sub' => '42'])->assertUnauthorized();

    expect($user->fresh()->sso_logged_out_at)->toBeNull();
});

it('rejects a replayed call', function () {
    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    signedCall(['sub' => '42', 'issued_at' => Carbon::now()->subHour()->getTimestamp()])
        ->assertStatus(400);

    expect($user->fresh()->sso_logged_out_at)->toBeNull();
});

it('rejects a signed call that names no usable subject', function (array $subject) {
    $unlinked = User::create(['name' => 'Someone Else', 'email' => 's@example.test']);
    $blank = User::create(['name' => 'Blank', 'email' => 'b@example.test', 'idp_id' => '']);

    signedCall([...$subject, 'issued_at' => Carbon::now()->getTimestamp()])
        ->assertStatus(400)
        ->assertJson(['error' => 'invalid_request']);

    expect($unlinked->fresh()->sso_logged_out_at)->toBeNull()
        ->and($blank->fresh()->sso_logged_out_at)->toBeNull();
})->with([
    'missing' => [[]],
    'null' => [['sub' => null]],
    'empty' => [['sub' => '']],
    'boolean' => [['sub' => true]],
    'array' => [['sub' => ['42']]],
]);

it('refuses every call when no secret is configured', function () {
    config()->set('id-client.logout_secret', null);

    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    signedCall(['sub' => '42', 'issued_at' => Carbon::now()->getTimestamp()])
        ->assertStatus(501);

    expect($user->fresh()->sso_logged_out_at)->toBeNull();
});

it('leaves other users alone', function () {
    $target = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);
    $bystander = User::create(['name' => 'Other', 'email' => 'o@example.test', 'idp_id' => '43']);

    signedCall(['sub' => '42', 'issued_at' => Carbon::now()->getTimestamp()])->assertOk();

    expect($target->fresh()->sso_logged_out_at)->not->toBeNull()
        ->and($bystander->fresh()->sso_logged_out_at)->toBeNull();
});

it('ends a local session established before the logout', function () {
    Route::middleware('web')->get('/protected', fn () => 'still in');

    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    $this->actingAs($user)
        ->withSession([EnsureSsoSessionIsActive::AUTHENTICATED_AT => Carbon::now()->subMinute()->getTimestamp()])
        ->get('/protected')
        ->assertOk();

    $user->forceFill(['sso_logged_out_at' => Carbon::now()])->save();

    $this->actingAs($user)
        ->withSession([EnsureSsoSessionIsActive::AUTHENTICATED_AT => Carbon::now()->subMinute()->getTimestamp()])
        ->get('/protected')
        ->assertRedirect('/');

    expect(Auth::check())->toBeFalse();
});

it('keeps a session established after the logout', function () {
    Route::middleware('web')->get('/protected', fn () => 'still in');

    $user = User::create([
        'name' => 'Robbin',
        'email' => 'r@example.test',
        'idp_id' => '42',
        'sso_logged_out_at' => Carbon::now()->subHour(),
    ]);

    // Signing back in after a single logout must not be undone by the stamp
    // that ended the previous session.
    $this->actingAs($user)
        ->withSession([EnsureSsoSessionIsActive::AUTHENTICATED_AT => Carbon::now()->getTimestamp()])
        ->get('/protected')
        ->assertOk();
});

it('leaves a session with no stamp alone', function () {
    Route::middleware('web')->get('/protected', fn () => 'still in');

    $user = User::create([
        'name' => 'Robbin',
        'email' => 'r@example.test',
        'idp_id' => '42',
        'sso_logged_out_at' => Carbon::now(),
    ]);

    $this->actingAs($user)->get('/protected')->assertOk();
});

it('ends the session when the app does not cast the stamp', function () {
    Route::middleware('web')->get('/protected', fn () => 'still in');

    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    signedCall(['sub' => '42', 'issued_at' => Carbon::now()->getTimestamp()])->assertOk();

    // Loaded from the database the way the guard loads it. With no cast on the
    // model the stamp comes back as the raw string.
    $user = $user->fresh();

    expect($user->sso_logged_out_at)->toBeString();

    $this->actingAs($user)
        ->withSession([EnsureSsoSessionIsActive::AUTHENTICATED_AT => Carbon::now()->subMinute()->getTimestamp()])
        ->get('/protected')
        ->assertRedirect('/');

    expect(Auth::check())->toBeFalse();
});

it('keeps a later session when the app does not cast the stamp', function () {
    Route::middleware('web')->get('/protected', fn () => 'still in');

    User::create([
        'name' => 'Robbin',
        'email' => 'r@example.test',
        'idp_id' => '42',
        'sso_logged_out_at' => Carbon::now()->subHour(),
    ]);

    $user = User::query()->where('idp_id', '42')->sole();

    expect($user->sso_logged_out_at)->toBeString();

    $this->actingAs($user)
        ->withSession([EnsureSsoSessionIsActive::AUTHENTICATED_AT => Carbon::now()->subMinutes(30)->getTimestamp()])
        ->get('/protected')
        ->assertOk();
});

it('stops a remember-me cookie from signing the user back in', function (string $event) {
    Route::middleware('web')->get('/whoami', fn () => Auth::check() ? 'signed in' : 'guest');

    // With a password, as an account adopted from a pre-SSO login has. Recent
    // Laravel refuses a remember-me cookie for a user without one.
    $user = User::create([
        'name' => 'Robbin',
        'email' => 'r@example.test',
        'idp_id' => '42',
        'password' => Hash::make('pre-sso-password'),
    ]);
    $guard = Auth::guard(config('id-client.guard'));
    $recaller = $guard->getRecallerName();

    // The same call SsoController makes on every sign-in.
    $guard->login($user, remember: true);
    $cookie = Cookie::queued($recaller)->getValue();

    // A browser coming back after its session expired, carrying nothing but
    // the remember-me cookie.
    $returningVisit = function () use ($recaller, $cookie) {
        Auth::forgetGuards();
        $this->flushSession();

        return $this->withCookie($recaller, $cookie)->get('/whoami');
    };

    $returningVisit()->assertContent('signed in');

    signedCall(['event' => $event, 'sub' => '42', 'issued_at' => Carbon::now()->getTimestamp()])->assertOk();

    // Later, so the cookie itself decides rather than a same-second stamp.
    $this->travel(1)->minute();

    $returningVisit()->assertContent('guest');
})->with(['logout', 'access.revoked']);

it('ends a session the remember-me cookie restored before the logout', function () {
    Route::middleware('web')->get('/whoami', fn () => Auth::check() ? 'signed in' : 'guest');

    $user = User::create([
        'name' => 'Robbin',
        'email' => 'r@example.test',
        'idp_id' => '42',
        'password' => Hash::make('pre-sso-password'),
    ]);
    $guard = Auth::guard(config('id-client.guard'));
    $recaller = $guard->getRecallerName();

    $guard->login($user, remember: true);
    $cookie = Cookie::queued($recaller)->getValue();

    // The session expired and the cookie alone starts a new one.
    Auth::forgetGuards();
    $this->flushSession();
    $this->withCookie($recaller, $cookie)->get('/whoami')->assertContent('signed in');

    $this->travel(1)->minute();

    signedCall(['sub' => '42', 'issued_at' => Carbon::now()->getTimestamp()])->assertOk();

    // The restored session's next request, which the guard answers from the
    // session rather than the cookie.
    Auth::forgetGuards();
    $this->get('/whoami')->assertRedirect('/');

    expect(Auth::check())->toBeFalse();
});

it('does not stamp a session whose remember-me cookie was refused', function () {
    Route::middleware('web')->get('/whoami', function () {
        return Auth::check() ? 'signed in' : (session()->has(EnsureSsoSessionIsActive::AUTHENTICATED_AT) ? 'guest, stamped' : 'guest');
    });

    // No password: Laravel refuses to restore a session from the cookie for
    // such a user, but only after it has already flagged the request viaRemember.
    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);
    $guard = Auth::guard(config('id-client.guard'));
    $recaller = $guard->getRecallerName();
    $guard->login($user, remember: true);
    $cookie = Cookie::queued($recaller)->getValue();

    Auth::forgetGuards();
    $this->flushSession();

    $this->withCookie($recaller, $cookie)->get('/whoami')->assertContent('guest');
});

it('stamps the logout on a model that opts out of remember tokens', function () {
    config()->set('id-client.user_model', UserWithoutRememberToken::class);

    $user = UserWithoutRememberToken::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    signedCall(['sub' => '42', 'issued_at' => Carbon::now()->getTimestamp()])->assertOk();

    expect($user->fresh()->sso_logged_out_at)->not->toBeNull();
});
