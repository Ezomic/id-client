<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient\Http\Middleware;

use Carbon\CarbonImmutable;
use Closure;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class EnsureSsoSessionIsActive
{
    public const AUTHENTICATED_AT = 'id_client.authenticated_at';

    /**
     * Ends a local session whose ID session has since signed out. Comparing
     * timestamps rather than tracking session ids keeps this working on every
     * session driver, and costs nothing extra: the user is already loaded.
     *
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $guard = Auth::guard(config('id-client.guard'));
        $user = $guard->user();

        // A session the remember-me cookie restores never passed through the
        // SSO callback, so it has no stamp and a later logout would leave it be.
        if ($guard->viaRemember() && ! $request->session()->has(self::AUTHENTICATED_AT)) {
            $request->session()->put(self::AUTHENTICATED_AT, Carbon::now()->getTimestamp());
        }

        if ($user instanceof Model && $this->signedOutAtIdp($request, $user)) {
            $guard->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return redirect('/');
        }

        return $next($request);
    }

    private function signedOutAtIdp(Request $request, Model $user): bool
    {
        $loggedOutAt = $user->getAttribute('sso_logged_out_at');

        if ($loggedOutAt === null) {
            return false;
        }

        $authenticatedAt = $request->session()->get(self::AUTHENTICATED_AT);

        // A session with no stamp predates this feature, or was not established
        // through SSO. Either way there is nothing to compare, so leave it be.
        if (! is_int($authenticatedAt)) {
            return false;
        }

        // The package adds the column but has no say over the consumer's model,
        // so an app that does not cast it hands back the raw database string.
        if (! $loggedOutAt instanceof DateTimeInterface) {
            $loggedOutAt = CarbonImmutable::parse($loggedOutAt);
        }

        return $loggedOutAt->getTimestamp() >= $authenticatedAt;
    }
}
