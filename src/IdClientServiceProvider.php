<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory as Socialite;
use Thijssensoftware\IdClient\Http\Controllers\SsoController;

class IdClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/id-client.php', 'id-client');

        config()->set('services.thijssensoftware', array_merge([
            'base_url' => env('THIJSSENSOFTWARE_ID_URL', 'https://id.thijssensoftware.nl'),
            'client_id' => env('THIJSSENSOFTWARE_ID_CLIENT_ID'),
            'client_secret' => env('THIJSSENSOFTWARE_ID_CLIENT_SECRET'),
            'redirect' => env('THIJSSENSOFTWARE_ID_REDIRECT', '/auth/sso/callback'),
        ], (array) config('services.thijssensoftware', [])));
    }

    public function boot(): void
    {
        $this->registerSocialiteDriver();
        $this->registerRoutes();
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        $this->publishes([
            __DIR__.'/../config/id-client.php' => config_path('id-client.php'),
        ], 'id-client-config');
    }

    private function registerSocialiteDriver(): void
    {
        $socialite = $this->app->make(Socialite::class);

        $socialite->extend('thijssensoftware', function () use ($socialite) {
            $config = config('services.thijssensoftware');

            return $socialite->buildProvider(ThijssensoftwareProvider::class, $config);
        });
    }

    private function registerRoutes(): void
    {
        Route::middleware('web')->group(function () {
            Route::get('auth/sso/redirect', [SsoController::class, 'redirect'])->name('sso.redirect');
            Route::get('auth/sso/callback', [SsoController::class, 'callback'])->name('sso.callback');
        });
    }
}
