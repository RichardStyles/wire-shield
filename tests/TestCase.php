<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Tests;

use Livewire\LivewireServiceProvider;
use Livewire\Mechanisms\HandleRequests\EndpointResolver;
use Orchestra\Testbench\TestCase as Orchestra;
use RichardStyles\WireShield\WireShieldServiceProvider;

abstract class TestCase extends Orchestra
{
    protected string $updatePath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->updatePath = EndpointResolver::updatePath();
    }

    protected function getPackageProviders($app): array
    {
        return [
            LivewireServiceProvider::class,
            WireShieldServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    }
}
