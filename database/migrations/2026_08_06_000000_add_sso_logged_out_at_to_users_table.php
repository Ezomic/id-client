<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Back-channel logout arrives on a server-to-server request with no session
 * cookie, so it cannot reach into the user's session directly. It stamps this
 * column instead, and the middleware turns that into a sign-out on the user's
 * next request. Works on any session driver.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasColumn('users', 'sso_logged_out_at')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            $table->timestamp('sso_logged_out_at')->nullable();
        });
    }

    public function down(): void
    {
        if (! Schema::hasColumn('users', 'sso_logged_out_at')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('sso_logged_out_at');
        });
    }
};
