<?php

declare(strict_types=1);

use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;
use RichardStyles\WireShield\Listeners\AbstractNotificationListener;
use RichardStyles\WireShield\Listeners\AbstractThreatListener;

test('AbstractThreatListener helper methods work correctly', function (): void {
    $listener = new class extends AbstractThreatListener
    {
        public function handle(LivewireDeserializationAttempt $event): void
        {
            // Not used in this test
        }

        public function testHelpers(LivewireDeserializationAttempt $event): array
        {
            return [
                'has_critical' => $this->hasCriticalThreats($event),
                'has_high' => $this->hasHighThreats($event),
                'highest_severity' => $this->getHighestSeverity($event),
                'unique_types' => $this->getUniqueTypes($event),
                'should_handle_medium' => $this->shouldHandle($event, 'medium'),
                'should_handle_high' => $this->shouldHandle($event, 'high'),
                'should_handle_critical' => $this->shouldHandle($event, 'critical'),
                'summary' => $this->formatSummary($event),
                'context' => $this->buildContext($event),
            ];
        }
    };

    $event = new LivewireDeserializationAttempt(
        ipAddress: '192.168.1.1',
        userAgent: 'Test Agent',
        requestPath: '/livewire/update',
        threats: [
            ['type' => 'known_gadget_class', 'severity' => 'critical', 'component_index' => 0, 'path' => 'test', 'detail' => 'Test threat 1'],
            ['type' => 'dangerous_callable', 'severity' => 'medium', 'component_index' => 0, 'path' => 'test', 'detail' => 'Test threat 2'],
            ['type' => 'unknown_synthesizer_key', 'severity' => 'high', 'component_index' => 0, 'path' => 'test', 'detail' => 'Test threat 3'],
        ],
        timestamp: '2024-01-01T00:00:00Z',
    );

    $results = $listener->testHelpers($event);

    expect($results['has_critical'])->toBeTrue();
    expect($results['has_high'])->toBeTrue();
    expect($results['highest_severity'])->toBe('critical');
    expect($results['unique_types'])->toBe(['known_gadget_class', 'dangerous_callable', 'unknown_synthesizer_key']);
    expect($results['should_handle_medium'])->toBeTrue();
    expect($results['should_handle_high'])->toBeTrue();
    expect($results['should_handle_critical'])->toBeTrue();
    expect($results['summary'])->toContain('CRITICAL');
    expect($results['summary'])->toContain('192.168.1.1');
    expect($results['context'])->toHaveKeys(['ip', 'user_agent', 'path', 'timestamp', 'threat_count', 'severity', 'threat_types', 'threats']);
});

test('AbstractNotificationListener respects minimum severity threshold', function (): void {
    $listener = new class extends AbstractNotificationListener
    {
        public bool $notificationSent = false;

        protected function getMinimumSeverity(): string
        {
            return 'critical';
        }

        protected function sendNotification(LivewireDeserializationAttempt $event): void
        {
            $this->notificationSent = true;
        }
    };

    $event = new LivewireDeserializationAttempt(
        ipAddress: '192.168.1.1',
        userAgent: 'Test Agent',
        requestPath: '/livewire/update',
        threats: [
            ['type' => 'dangerous_callable', 'severity' => 'medium', 'component_index' => 0, 'path' => 'test', 'detail' => 'Medium threat'],
        ],
        timestamp: '2024-01-01T00:00:00Z',
    );

    $listener->handle($event);

    expect($listener->notificationSent)->toBeFalse();
});

test('AbstractNotificationListener rate limiting works', function (): void {
    $cacheData = [];

    $listener = new class($cacheData) extends AbstractNotificationListener
    {
        public int $notificationCount = 0;

        private array $cache;

        public function __construct(array &$cache)
        {
            $this->cache = &$cache;
        }

        protected function getMinimumSeverity(): string
        {
            return 'critical';
        }

        protected function shouldRateLimit(): bool
        {
            return true;
        }

        protected function getRateLimitSeconds(): int
        {
            return 60;
        }

        protected function isRateLimited(LivewireDeserializationAttempt $event): bool
        {
            return isset($this->cache[$this->getRateLimitKey($event)]);
        }

        protected function recordNotification(LivewireDeserializationAttempt $event): void
        {
            $this->cache[$this->getRateLimitKey($event)] = true;
        }

        protected function sendNotification(LivewireDeserializationAttempt $event): void
        {
            $this->notificationCount++;
        }
    };

    $event = new LivewireDeserializationAttempt(
        ipAddress: '192.168.1.1',
        userAgent: 'Test Agent',
        requestPath: '/livewire/update',
        threats: [
            ['type' => 'known_gadget_class', 'severity' => 'critical', 'component_index' => 0, 'path' => 'test', 'detail' => 'Critical threat'],
        ],
        timestamp: '2024-01-01T00:00:00Z',
    );

    // First notification should go through
    $listener->handle($event);
    expect($listener->notificationCount)->toBe(1);

    // Second notification should be rate limited
    $listener->handle($event);
    expect($listener->notificationCount)->toBe(1);
});
