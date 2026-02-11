<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Listeners;

use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;

abstract class AbstractThreatListener
{
    abstract public function handle(LivewireDeserializationAttempt $event): void;

    /**
     * Check if any threats are critical severity.
     */
    protected function hasCriticalThreats(LivewireDeserializationAttempt $event): bool
    {
        return $this->filterBySeverity($event, 'critical') !== [];
    }

    /**
     * Check if any threats are high severity.
     */
    protected function hasHighThreats(LivewireDeserializationAttempt $event): bool
    {
        return $this->filterBySeverity($event, 'high') !== [];
    }

    /**
     * Filter threats by severity level.
     *
     * @return array<int, array{type: string, severity: string, component_index: int, path: string, detail: string}>
     */
    protected function filterBySeverity(LivewireDeserializationAttempt $event, string $severity): array
    {
        return array_values(array_filter(
            $event->threats,
            fn (array $threat): bool => $threat['severity'] === $severity
        ));
    }

    /**
     * Filter threats by type.
     *
     * @return array<int, array{type: string, severity: string, component_index: int, path: string, detail: string}>
     */
    protected function filterByType(LivewireDeserializationAttempt $event, string $type): array
    {
        return array_values(array_filter(
            $event->threats,
            fn (array $threat): bool => $threat['type'] === $type
        ));
    }

    /**
     * Get unique threat types from the event.
     *
     * @return list<string>
     */
    protected function getUniqueTypes(LivewireDeserializationAttempt $event): array
    {
        return array_values(array_unique(array_column($event->threats, 'type')));
    }

    /**
     * Get the highest severity level from all threats.
     *
     * @return 'critical'|'high'|'medium'|null
     */
    protected function getHighestSeverity(LivewireDeserializationAttempt $event): ?string
    {
        $severities = array_column($event->threats, 'severity');

        if (in_array('critical', $severities, true)) {
            return 'critical';
        }

        if (in_array('high', $severities, true)) {
            return 'high';
        }

        if (in_array('medium', $severities, true)) {
            return 'medium';
        }

        return null;
    }

    /**
     * Check if the listener should handle this event based on severity threshold.
     */
    protected function shouldHandle(LivewireDeserializationAttempt $event, string $minimumSeverity = 'medium'): bool
    {
        $severity = $this->getHighestSeverity($event);

        if ($severity === null) {
            return false;
        }

        $severityOrder = ['medium' => 1, 'high' => 2, 'critical' => 3];

        return $severityOrder[$severity] >= $severityOrder[$minimumSeverity];
    }

    /**
     * Format the event as a human-readable summary.
     */
    protected function formatSummary(LivewireDeserializationAttempt $event): string
    {
        $severity = $this->getHighestSeverity($event);
        $types = $this->getUniqueTypes($event);

        return sprintf(
            '[%s] Livewire threat from %s - %d threat(s) detected: %s',
            strtoupper($severity ?? 'unknown'),
            $event->ipAddress,
            count($event->threats),
            implode(', ', $types)
        );
    }

    /**
     * Create context array for logging.
     *
     * @return array<string, mixed>
     */
    protected function buildContext(LivewireDeserializationAttempt $event): array
    {
        return [
            'ip' => $event->ipAddress,
            'user_agent' => $event->userAgent,
            'path' => $event->requestPath,
            'timestamp' => $event->timestamp,
            'threat_count' => count($event->threats),
            'severity' => $this->getHighestSeverity($event),
            'threat_types' => $this->getUniqueTypes($event),
            'threats' => $event->threats,
        ];
    }
}
