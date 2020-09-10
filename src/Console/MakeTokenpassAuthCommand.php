<?php

namespace Tokenly\TokenpassClient\Console;

use Illuminate\Console\Command;

class MakeTokenpassAuthCommand extends Command
{

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'tokenpass:make-auth
        {--force : Overwrite existing views by default}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Scaffold Tokenpass authentication views';

    /**
     * The views that need to be exported.
     *
     * @var array
     */
    protected $views = [
        'layouts/base.stub' => 'layouts/base.blade.php',
        'layouts/app.stub' => 'layouts/app.blade.php',

        'partials/notifications.stub' => 'partials/notifications.blade.php',

        'auth/login.stub' => 'auth/login.blade.php',
        'auth/logout.stub' => 'auth/logout.blade.php',
        'auth/error.stub' => 'auth/error.blade.php',
        'auth/sync.stub' => 'auth/sync.blade.php',

        'home.stub' => 'home.blade.php',
    ];

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $this->createDirectories();

        $this->exportViews();

        $this->info('Tokenpass authentication views scaffolding generated successfully.');

        app('Tokenly\TokenpassClient\TokenpassAPI');
    }

    /**
     * Create the directories for the files.
     *
     * @return void
     */
    protected function createDirectories()
    {
        if (! is_dir($directory = resource_path('views/layouts'))) {
            mkdir($directory, 0755, true);
        }
        if (! is_dir($directory = resource_path('views/auth'))) {
            mkdir($directory, 0755, true);
        }
        if (! is_dir($directory = resource_path('views/partials'))) {
            mkdir($directory, 0755, true);
        }
    }

    /**
     * Export the authentication views.
     *
     * @return void
     */
    protected function exportViews()
    {
        foreach ($this->views as $key => $value) {
            if (file_exists($view = resource_path('views/'.$value)) && ! $this->option('force')) {
                if (! $this->confirm("The [{$value}] view already exists. Do you want to replace it?")) {
                    continue;
                }
            }

            copy(
                __DIR__.'/stubs/make/views/'.$key,
                $view
            );
        }
    }

}
