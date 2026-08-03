<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Laravel\Socialite\Contracts\Factory as Socialite;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Symfony\Component\HttpFoundation\Response;
use Thijssensoftware\IdClient\Exceptions\AccessDeniedException;

class SsoController extends Controller
{
    public function __construct(private readonly Socialite $socialite) {}

    public function redirect(): mixed
    {
        return $this->socialite->driver('thijssensoftware')->redirect();
    }

    public function callback(): RedirectResponse
    {
        try {
            $idUser = $this->socialite->driver('thijssensoftware')->user();
        } catch (AccessDeniedException $e) {
            abort(Response::HTTP_FORBIDDEN, $e->getMessage());
        }

        $user = $this->resolveUser($idUser);

        abort_if($user === null, Response::HTTP_FORBIDDEN, 'No account for this user.');

        Auth::guard(config('id-client.guard'))->login($user, remember: true);

        return redirect()->intended(config('id-client.home'));
    }

    private function resolveUser(SocialiteUser $idUser): ?Authenticatable
    {
        /** @var class-string<Model&Authenticatable> $model */
        $model = config('id-client.user_model');

        $email = $this->resolveEmail($idUser);

        $user = $model::query()->where('idp_id', $idUser->getId())->first()
            ?? $this->findByEmail($model, $email);

        if ($user === null) {
            // Without an email there is nothing to provision against: the column is
            // required, and it is the only identifier besides the idp id we just failed
            // to match on.
            if (! config('id-client.provision') || $email === null) {
                return null;
            }

            $user = new $model;
        }

        $user->forceFill([
            'idp_id' => $idUser->getId(),
            'name' => $this->resolveName($idUser, $user->name, $email),
            'email' => $email ?? $user->email,
        ])->save();

        return $user;
    }

    /**
     * An id server that sends no email leaves nothing to match a local account on.
     * Passing that null to the query builder would compile to `where email is null`
     * and match an unrelated account, so absent is represented as null and never
     * reaches a query.
     */
    private function resolveEmail(SocialiteUser $idUser): ?string
    {
        $email = $idUser->getEmail();

        return $email === null || $email === '' ? null : $email;
    }

    /**
     * @param  class-string<Model&Authenticatable>  $model
     */
    private function findByEmail(string $model, ?string $email): ?Authenticatable
    {
        if ($email === null) {
            return null;
        }

        return $model::query()->where('email', $email)->first();
    }

    /**
     * The users table requires a name, and a user being provisioned for the first time
     * has no local one to fall back to, so derive one rather than writing null.
     */
    private function resolveName(SocialiteUser $idUser, ?string $current, ?string $email): string
    {
        return $idUser->getName()
            ?: $current
            ?: Str::before((string) $email, '@')
            ?: (string) $idUser->getId();
    }
}
