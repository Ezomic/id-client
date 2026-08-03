<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The host application owns the users table; the package only adds a column to it.
 * This stands in for that table so the package migration has something to alter.
 * The 0001_01_01 prefix keeps it ahead of the package migration, which the migrator
 * orders by filename across every registered path.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            // Deliberately nullable, unlike Laravel's default. An SSO-only host may well
            // permit null emails, and that is the schema the callback's email matching has
            // to stay safe on, so the suite has to be able to express it.
            $table->string('email')->nullable()->unique();
            $table->string('password')->nullable();
            $table->rememberToken();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
