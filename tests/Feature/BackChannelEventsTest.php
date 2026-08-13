<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Thijssensoftware\IdClient\Tests\Fixtures\User;

const EVENT_SECRET = 'shared-logout-secret';

function signedEvent(array $payload)
{
    $body = json_encode($payload, JSON_THROW_ON_ERROR);

    return test()->call('POST', '/auth/sso/logout', server: [
        'HTTP_X_ID_SIGNATURE' => hash_hmac('sha256', $body, EVENT_SECRET),
        'CONTENT_TYPE' => 'application/json',
    ], content: $body);
}

beforeEach(function () {
    config()->set('id-client.logout_secret', EVENT_SECRET);
});

it('ends the session on access.revoked', function () {
    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    signedEvent([
        'event' => 'access.revoked',
        'sub' => '42',
        'issued_at' => Carbon::now()->getTimestamp(),
    ])->assertOk();

    // Revocation only reached a consumer as a token that stopped refreshing,
    // leaving the user sitting in a working local session.
    expect($user->fresh()->sso_logged_out_at)->not->toBeNull();
});

it('refreshes the local copy on user.updated', function () {
    $user = User::create(['name' => 'Old Name', 'email' => 'old@example.test', 'idp_id' => '42']);

    signedEvent([
        'event' => 'user.updated',
        'sub' => '42',
        'name' => 'New Name',
        'email' => 'new@example.test',
        'issued_at' => Carbon::now()->getTimestamp(),
    ])->assertOk();

    $user->refresh();

    expect($user->name)->toBe('New Name')
        ->and($user->email)->toBe('new@example.test')
        // A profile change is not a sign-out.
        ->and($user->sso_logged_out_at)->toBeNull();
});

it('ignores an event type it does not know', function () {
    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    // Upgrading ID must not break a consumer that has not caught up yet.
    signedEvent([
        'event' => 'something.from.the.future',
        'sub' => '42',
        'issued_at' => Carbon::now()->getTimestamp(),
    ])->assertOk()->assertJson(['status' => 'ignored']);

    expect($user->fresh()->sso_logged_out_at)->toBeNull();
});

it('treats a payload with no event as a logout', function () {
    $user = User::create(['name' => 'Robbin', 'email' => 'r@example.test', 'idp_id' => '42']);

    // A pre-0.3 ID server only ever sent logouts and sent no event field.
    signedEvent([
        'sub' => '42',
        'issued_at' => Carbon::now()->getTimestamp(),
    ])->assertOk();

    expect($user->fresh()->sso_logged_out_at)->not->toBeNull();
});

it('still verifies the signature on every event type', function () {
    $user = User::create(['name' => 'Old Name', 'email' => 'old@example.test', 'idp_id' => '42']);

    $body = json_encode(['event' => 'user.updated', 'sub' => '42', 'name' => 'Hijacked'], JSON_THROW_ON_ERROR);

    test()->call('POST', '/auth/sso/logout', server: [
        'HTTP_X_ID_SIGNATURE' => hash_hmac('sha256', $body, 'wrong-secret'),
        'CONTENT_TYPE' => 'application/json',
    ], content: $body)->assertUnauthorized();

    expect($user->fresh()->name)->toBe('Old Name');
});

it('leaves other users alone on a profile update', function () {
    $target = User::create(['name' => 'Target', 'email' => 't@example.test', 'idp_id' => '42']);
    $bystander = User::create(['name' => 'Bystander', 'email' => 'b@example.test', 'idp_id' => '43']);

    signedEvent([
        'event' => 'user.updated',
        'sub' => '42',
        'name' => 'Renamed',
        'issued_at' => Carbon::now()->getTimestamp(),
    ])->assertOk();

    expect($target->fresh()->name)->toBe('Renamed')
        ->and($bystander->fresh()->name)->toBe('Bystander');
});
