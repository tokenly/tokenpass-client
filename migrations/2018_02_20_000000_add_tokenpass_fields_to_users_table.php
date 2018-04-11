<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;

class AddTokenpassFieldsToUsersTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            if (!Schema::hasColumn($table->getTable(), 'confirmed_email')) {
                $table->string('confirmed_email')->nullable()->unique();
            }
            if (!Schema::hasColumn($table->getTable(), 'tokenly_uuid')) {
                $table->char('tokenly_uuid', 36)->nullable()->unique();
            }
            if (!Schema::hasColumn($table->getTable(), 'oauth_token')) {
                $table->text('oauth_token')->nullable();
            }
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
    }
}
