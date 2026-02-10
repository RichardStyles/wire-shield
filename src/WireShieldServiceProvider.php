<?php

declare(strict_types=1);

namespace RichardStyles\WireShield;

use Illuminate\Routing\Router;
use RichardStyles\WireShield\Http\Middleware\ScanLivewirePayloads;
use RichardStyles\WireShield\Http\Middleware\ThrottleSuspiciousRequests;
use RichardStyles\WireShield\Http\Middleware\ValidateLivewirePayloadSize;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class WireShieldServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('wire-shield')
            ->hasConfigFile();
    }

    public function packageBooted(): void
    {
        if (config('wire-shield.enabled', true)) {
            /** @var Router $router */
            $router = $this->app->make('router');

            // Payload size check first (cheapest rejection)
            $router->pushMiddlewareToGroup('web', ValidateLivewirePayloadSize::class);

            // Consolidated payload scanner
            $router->pushMiddlewareToGroup('web', ScanLivewirePayloads::class);

            // Repeat offender tracking (must be last — reads threat attributes)
            $router->pushMiddlewareToGroup('web', ThrottleSuspiciousRequests::class);
        }
    }
}
