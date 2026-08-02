<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory as Socialite;
use Thijssensoftware\IdClient\IdClientServiceProvider;
use Thijssensoftware\IdClient\ThijssensoftwareProvider;

it('merges the package config', function (): void {
    expect(config('id-client.guard'))->toBe('web')
        ->and(config('id-client.home'))->toBe('/dashboard')
        ->and(config('id-client.provision'))->toBeTrue();
});

it('registers the sso routes on the web middleware group', function (): void {
    $redirect = Route::getRoutes()->getByName('sso.redirect');
    $callback = Route::getRoutes()->getByName('sso.callback');

    expect($redirect)->not->toBeNull()
        ->and($redirect->uri())->toBe('auth/sso/redirect')
        ->and($redirect->gatherMiddleware())->toContain('web')
        ->and($callback)->not->toBeNull()
        ->and($callback->uri())->toBe('auth/sso/callback')
        ->and($callback->gatherMiddleware())->toContain('web');
});

it('registers the thijssensoftware socialite driver', function (): void {
    $driver = app(Socialite::class)->driver('thijssensoftware');

    expect($driver)->toBeInstanceOf(ThijssensoftwareProvider::class);
});

it('offers the config for publishing under its own tag', function (): void {
    $paths = ServiceProvider::pathsToPublish(IdClientServiceProvider::class, 'id-client-config');

    expect($paths)->toHaveCount(1)
        ->and(array_key_first($paths))->toEndWith('config/id-client.php')
        ->and(array_values($paths)[0])->toEndWith('config/id-client.php');
});

it('registers the migration that adds idp_id to users', function (): void {
    expect(Schema::hasColumn('users', 'idp_id'))->toBeTrue();
});
