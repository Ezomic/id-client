<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasColumn('users', 'idp_id')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            $table->string('idp_id')->nullable()->unique()->after('email');
        });
    }

    public function down(): void
    {
        if (! Schema::hasColumn('users', 'idp_id')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            $table->dropUnique(['idp_id']);
            $table->dropColumn('idp_id');
        });
    }
};
