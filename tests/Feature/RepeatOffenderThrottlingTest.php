<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;
use RichardStyles\WireShield\Events\RepeatOffenderDetected;

beforeEach(function () {
    config(['wire-shield.throttle_offenders' => true]);
    RateLimiter::clear('wire-shield:offender:127.0.0.1');
});

function maliciousPayload(): array
{
    return livewirePayload(
        updates: ['name' => ['payload', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']]],
    );
}

function seedStrikes(int $count): void
{
    $decaySeconds = (int) config('wire-shield.offender_decay_minutes', 60) * 60;

    for ($i = 0; $i < $count; $i++) {
        RateLimiter::hit('wire-shield:offender:127.0.0.1', $decaySeconds);
    }
}

test('first offense only logs, does not throttle', function () {
    Event::fake([LivewireDeserializationAttempt::class, RepeatOffenderDetected::class]);

    $response = $this->postJson($this->updatePath, maliciousPayload(), ['X-Livewire' => '1']);

    $response->assertStatus(500);

    Event::assertDispatched(RepeatOffenderDetected::class, function ($event) {
        return $event->escalationLevel === 'warning' && $event->strikeCount === 1;
    });
});

test('third offense returns 429 with retry-after', function () {
    Event::fake([LivewireDeserializationAttempt::class, RepeatOffenderDetected::class]);

    seedStrikes(2);

    $response = $this->postJson($this->updatePath, maliciousPayload(), ['X-Livewire' => '1']);

    $response->assertStatus(429);
    $response->assertHeader('Retry-After');

    Event::assertDispatched(RepeatOffenderDetected::class, function ($event) {
        return $event->escalationLevel === 'throttle' && $event->strikeCount === 3;
    });
});

test('sixth offense returns 403', function () {
    Event::fake([LivewireDeserializationAttempt::class, RepeatOffenderDetected::class]);

    seedStrikes(5);

    $response = $this->postJson($this->updatePath, maliciousPayload(), ['X-Livewire' => '1']);

    $response->assertStatus(403);

    Event::assertDispatched(RepeatOffenderDetected::class, function ($event) {
        return $event->escalationLevel === 'block' && $event->strikeCount === 6;
    });
});

test('blocked IP gets 403 immediately on subsequent requests', function () {
    Event::fake([LivewireDeserializationAttempt::class, RepeatOffenderDetected::class]);

    seedStrikes(6);

    $response = $this->postJson($this->updatePath, maliciousPayload(), ['X-Livewire' => '1']);

    $response->assertStatus(403);
});

test('clean IP passes through', function () {
    Event::fake([LivewireDeserializationAttempt::class, RepeatOffenderDetected::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot(['name' => 'safe']),
        updates: ['name' => 'hello'],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(RepeatOffenderDetected::class);
});

test('disabled throttle config skips tracking', function () {
    config(['wire-shield.throttle_offenders' => false]);
    Event::fake([LivewireDeserializationAttempt::class, RepeatOffenderDetected::class]);

    seedStrikes(6);

    $response = $this->postJson($this->updatePath, maliciousPayload(), ['X-Livewire' => '1']);

    $response->assertStatus(500);

    Event::assertNotDispatched(RepeatOffenderDetected::class);
});
