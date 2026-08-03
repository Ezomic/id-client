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

        $user = $model::query()->where('idp_id', $idUser->getId())->first()
            ?? $model::query()->where('email', $idUser->getEmail())->first();

        if ($user === null) {
            if (! config('id-client.provision')) {
                return null;
            }

            $user = new $model;
        }

        $user->forceFill([
            'idp_id' => $idUser->getId(),
            'name' => $this->resolveName($idUser, $user->name),
            'email' => $idUser->getEmail(),
        ])->save();

        return $user;
    }

    /**
     * The users table requires a name, and a user being provisioned for the first time
     * has no local one to fall back to, so derive one rather than writing null.
     */
    private function resolveName(SocialiteUser $idUser, ?string $current): string
    {
        return $idUser->getName()
            ?: $current
            ?: Str::before((string) $idUser->getEmail(), '@');
    }
}
