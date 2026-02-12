<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;

test('normal livewire requests pass through', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot(['name' => 'test']),
        updates: ['name' => 'hello world'],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('detects known gadget class in updates', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['name' => ['malicious_data', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'known_gadget_class');
    });
});

test('detects unexpected class in synthetic tuple', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['name' => ['data', ['s' => 'str', 'class' => 'Some\\Unknown\\EvilClass']]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'unexpected_class_in_update');
    });
});

test('detects unknown synthesizer key', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['name' => ['data', ['s' => 'evil_synth']]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'unknown_synthesizer_key');
    });
});

test('detects dangerous callable in values', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['command' => 'system'],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'dangerous_callable');
    });
});

test('blocking mode returns 403', function () {
    config(['wire-shield.block_suspicious_requests' => true]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $response = $this->postJson($this->updatePath, livewirePayload(
        updates: ['name' => ['payload', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']]],
    ), ['X-Livewire' => '1']);

    $response->assertStatus(403);
});

test('disabled middleware does nothing', function () {
    config(['wire-shield.enabled' => false]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['name' => ['payload', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']]],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('non livewire requests to other routes are ignored', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson('/not-livewire', livewirePayload(
        snapshot: '{}',
        updates: ['name' => ['payload', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']]],
    ));

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('detects threats on livewire route without X-Livewire header', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['name' => ['payload', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']]],
    ));

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'known_gadget_class');
    });
});

test('detects threats in call parameters', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => 'save', 'params' => [['evil', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']]]]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'known_gadget_class');
    });
});

test('detects all configured dangerous classes', function (string $class) {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['name' => ['payload', ['s' => 'str', 'class' => $class]]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'known_gadget_class');
    });
})->with([
    'GuzzleHttp\\Psr7\\FnStream',
    'GuzzleHttp\\Psr7\\AppendStream',
    'League\\Flysystem\\UrlGeneration\\ShardedPrefixPublicUrlGenerator',
    'Laravel\\SerializableClosure\\Serializers\\Signed',
    'Illuminate\\Broadcasting\\BroadcastEvent',
    'Illuminate\\Broadcasting\\PendingBroadcast',
    'Illuminate\\Bus\\Queueable',
    'Illuminate\\Container\\Container',
    'Illuminate\\Database\\Capsule\\Manager',
    'Illuminate\\Filesystem\\Filesystem',
    'Illuminate\\Foundation\\Testing\\PendingCommand',
    'Illuminate\\Mail\\Mailer',
    'Illuminate\\Queue\\CallQueuedClosure',
    'Symfony\\Component\\Process\\Process',
    'Symfony\\Component\\Finder\\Finder',
    'Monolog\\Handler\\SyslogUdpHandler',
    'Monolog\\Handler\\NativeMailerHandler',
    'Faker\\Generator',
    'Carbon\\CarbonInterval',
    'PhpParser\\NodeTraverser',
    'Doctrine\\Instantiator\\Instantiator',
]);

test('detects suspicious update property name', function (string $property) {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: [$property => []],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'suspicious_property_update');
    });
})->with([
    'areFormStateUpdateHooksDisabledForTesting',
    'activeComponent',
    'cachedMountedTableAction',
    'cachedMountedTableBulkAction',
    'cachedMountedTableActionRecord',
    'mountedActions',
    'mountedActionsArguments',
    'mountedActionsData',
]);

test('detects suspicious property with prefix matching', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['activeComponentId' => []],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'suspicious_property_update');
    });
});

test('normal property names are not flagged as suspicious', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot(['name' => 'test', 'email' => 'test@example.com']),
        updates: ['name' => 'hello', 'email' => 'new@example.com'],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('suspicious property with blocking mode returns 403', function () {
    config(['wire-shield.block_suspicious_requests' => true]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $response = $this->postJson($this->updatePath, livewirePayload(
        updates: ['areFormStateUpdateHooksDisabledForTesting' => []],
    ), ['X-Livewire' => '1']);

    $response->assertStatus(403);
});

test('event carries correct metadata', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['name' => ['data', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return $event->ipAddress === '127.0.0.1'
            && ! empty($event->requestPath)
            && ! empty($event->timestamp)
            && count($event->threats) > 0;
    });
});

test('detects path traversal in update values', function (string $payload) {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['search' => $payload],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'path_traversal_attempt');
    });
})->with([
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32',
    'some/path/../../../secret',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f',
    '%2e%2e%5c%2e%2e%5c',
    '%252e%252e%252f',
]);

test('detects path traversal in call parameters', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => 'search', 'params' => ['../../../']]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'path_traversal_attempt');
    });
});

test('detects path traversal in nested structures', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['filters' => ['path' => '../../../secret']],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'path_traversal_attempt');
    });
});

test('disabled scan_path_traversal config skips path traversal scanning', function () {
    config(['wire-shield.scan_path_traversal' => false]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['search' => '../../../etc/passwd'],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('path traversal with blocking mode returns 403', function () {
    config(['wire-shield.block_suspicious_requests' => true]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $response = $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => 'inline-search', 'params' => ['../../../']]],
    ), ['X-Livewire' => '1']);

    $response->assertStatus(403);
});

test('normal file paths are not flagged as traversal', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: [
            'path' => '/var/www/html/public',
            'file' => 'document.pdf',
            'url' => 'https://example.com/path/to/file',
        ],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('detects real world attack with magic method and path traversal', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    // Real attack payload observed in the wild
    $this->postJson($this->updatePath, livewirePayload(
        calls: [
            [
                'method' => '__foobar',
                'params' => [
                    'inline-search',
                    '{"search":"../../../"}',
                ],
                'path' => '',
            ],
        ],
        snapshot: '{"data":{"inlineResults":true},"memo":{"id":"test","name":"search-bar"},"checksum":"abc123"}',
        updates: [],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        $threats = collect($event->threats);

        // Should detect both the magic method pattern AND path traversal
        return $threats->contains('type', 'suspicious_magic_method_pattern')
            && $threats->contains('type', 'path_traversal_attempt')
            && $threats->count() >= 2;
    });
});
