<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Thijssensoftware\IdClient\Http\Middleware\EnsureSsoSessionIsActive;
use Thijssensoftware\IdClient\Tests\Fixtures\User;

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
