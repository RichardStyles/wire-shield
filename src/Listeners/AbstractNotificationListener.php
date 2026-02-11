<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Listeners;

use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;

abstract class AbstractNotificationListener extends AbstractThreatListener
{
    /**
     * Send the notification to the external service.
     */
    abstract protected function sendNotification(LivewireDeserializationAttempt $event): void;

    /**
     * Get the minimum severity level to notify. Options: 'medium', 'high', 'critical'.
     * By default, only notifies on critical threats.
     */
    protected function getMinimumSeverity(): string
    {
        return 'critical';
    }

    /**
     * Check if notifications should be rate limited.
     * Override to return true and implement getRateLimitKey() and getRateLimitSeconds().
     */
    protected function shouldRateLimit(): bool
    {
        return false;
    }

    /**
     * Get the cache key for rate limiting.
     */
    protected function getRateLimitKey(LivewireDeserializationAttempt $event): string
    {
        return sprintf('wire-shield:notification:%s', $event->ipAddress);
    }

    /**
     * Get the rate limit duration in seconds.
     */
    protected function getRateLimitSeconds(): int
    {
        return 300; // 5 minutes
    }

    public function handle(LivewireDeserializationAttempt $event): void
    {
        if (! $this->shouldHandle($event, $this->getMinimumSeverity())) {
            return;
        }

        if ($this->shouldRateLimit() && $this->isRateLimited($event)) {
            return;
        }

        $this->sendNotification($event);

        if ($this->shouldRateLimit()) {
            $this->recordNotification($event);
        }
    }

    /**
     * Check if a notification for this event is rate limited.
     */
    protected function isRateLimited(LivewireDeserializationAttempt $event): bool
    {
        return cache()->has($this->getRateLimitKey($event));
    }

    /**
     * Record that a notification was sent.
     */
    protected function recordNotification(LivewireDeserializationAttempt $event): void
    {
        cache()->put(
            $this->getRateLimitKey($event),
            true,
            $this->getRateLimitSeconds()
        );
    }

    /**
     * Format the notification title.
     */
    protected function formatTitle(LivewireDeserializationAttempt $event): string
    {
        $severity = $this->getHighestSeverity($event);

        return sprintf(
            '%s Livewire Security Threat Detected',
            strtoupper($severity ?? 'UNKNOWN')
        );
    }

    /**
     * Format the notification body with threat details.
     */
    protected function formatBody(LivewireDeserializationAttempt $event): string
    {
        $lines = [
            sprintf('IP Address: %s', $event->ipAddress),
            sprintf('Request Path: %s', $event->requestPath),
            sprintf('Threats Detected: %d', count($event->threats)),
            sprintf('Threat Types: %s', implode(', ', $this->getUniqueTypes($event))),
            '',
            'Details:',
        ];

        foreach ($event->threats as $index => $threat) {
            $lines[] = sprintf(
                '%d. [%s] %s: %s',
                $index + 1,
                strtoupper($threat['severity']),
                $threat['type'],
                $threat['detail']
            );
        }

        return implode("\n", $lines);
    }
}
