<?php

class TestCase extends Orchestra\Testbench\TestCase {

    protected $useDatabase = false;


    public function setUp()
    {
        parent::setUp();

        if($this->useDatabase)
        {
            $this->setUpDb();
        }
    }

    public function setUpDb()
    {
        // // create an artisan object for calling migrations
        // $artisan = $this->app->make('Illuminate\Contracts\Console\Kernel');

        // // call migrations that will be part of your package, assumes your migrations are in src/migrations
        // // not neccessary if your package doesn't require any migrations to be run for
        // // proper installation
        // $artisan->call('migrate', [
        //     '--database' => 'testbench',
        //     '--path'     => 'migrations',
        // ]);

    }

    public function teardownDb()
    {
        // $this->app['Illuminate\Contracts\Console\Kernel']->call('migrate:reset');
    }


    // protected function resolveApplicationConfiguration($app) {
    //     parent::resolveApplicationConfiguration($app);
    //     // $app['config']['app.log'] = 'single';
    // }

    /**
     * Get package providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array
     */
    protected function getPackageProviders($app)
    {
        // return ['App\Listener\XChainListenerServiceProvider'];
        return [];
    }


    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function getEnvironmentSetUp($app)
    {
        // $app['config']['app.log'] = 'single';

        // $app['config']->set('database.default', 'testbench');
        // $app['config']->set('database.connections.testbench', array(
        //     'driver'   => 'sqlite',
        //     'database' => ':memory:',
        //     'prefix'   => '',
        // ));
    }

    // /**
    //  * Get base path.
    //  *
    //  * @return string
    //  */
    // protected function getBasePath()
    // {
    //     // reset base path to point to our package's src directory
    //     return __DIR__.'/../..';
    // }

}
