<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;

beforeEach(function () {
    config(['wire-shield.enforce_payload_size' => true]);
});

test('normal sized payload passes through', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $response = $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot(['name' => 'test']),
        updates: ['name' => 'test'],
    ), ['X-Livewire' => '1']);

    expect($response->getStatusCode())->not->toBe(413);
});

test('oversized payload returns 413', function () {
    config(['wire-shield.max_payload_bytes' => 100]);

    $response = $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot(['big' => str_repeat('x', 200)]),
    ), ['X-Livewire' => '1']);

    $response->assertStatus(413);
});

test('disabled enforce_payload_size skips check', function () {
    config([
        'wire-shield.enforce_payload_size' => false,
        'wire-shield.max_payload_bytes' => 100,
    ]);

    $response = $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot(['big' => str_repeat('x', 200)]),
    ), ['X-Livewire' => '1']);

    expect($response->getStatusCode())->not->toBe(413);
});

test('non livewire requests skip size check', function () {
    config(['wire-shield.max_payload_bytes' => 10]);

    $response = $this->postJson('/not-livewire', livewirePayload(
        snapshot: fakeSnapshot(['big' => str_repeat('x', 200)]),
    ));

    expect($response->getStatusCode())->not->toBe(413);
});
