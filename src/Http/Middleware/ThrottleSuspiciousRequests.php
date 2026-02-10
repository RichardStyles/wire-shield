<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use RichardStyles\WireShield\Concerns\ScansPayloads;
use RichardStyles\WireShield\Events\RepeatOffenderDetected;
use Symfony\Component\HttpFoundation\Response;

class ThrottleSuspiciousRequests
{
    use ScansPayloads;

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('wire-shield.throttle_offenders', false) || ! $this->isLivewireRequest($request)) {
            return $next($request);
        }

        $ip = (string) $request->ip();
        $limiterKey = "wire-shield:offender:{$ip}";
        $decayMinutes = (int) config('wire-shield.offender_decay_minutes', 60);
        $decaySeconds = $decayMinutes * 60;

        /** @var array{warning: int, throttle: int, block: int} $thresholds */
        $thresholds = config('wire-shield.offender_thresholds', [
            'warning' => 1,
            'throttle' => 3,
            'block' => 6,
        ]);

        // Check if this IP is already blocked before processing
        if (RateLimiter::tooManyAttempts($limiterKey, $thresholds['block'])) {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        // Let the request pass through other middleware first
        $response = $next($request);

        // Check if any scanner middleware flagged threats on this request
        $threats = $request->attributes->get('wire_shield_threats', []);

        if (empty($threats)) {
            return $response;
        }

        // Atomically increment strike count with decay TTL
        RateLimiter::hit($limiterKey, $decaySeconds);
        $strikes = RateLimiter::attempts($limiterKey);

        // Determine escalation level
        $level = 'warning';

        if ($strikes >= $thresholds['block']) {
            $level = 'block';
        } elseif ($strikes >= $thresholds['throttle']) {
            $level = 'throttle';
        }

        // Dispatch event when crossing a threshold boundary
        if ($strikes === $thresholds['warning']
            || $strikes === $thresholds['throttle']
            || $strikes === $thresholds['block']
        ) {
            RepeatOffenderDetected::dispatch(
                $ip,
                $strikes,
                $level,
                now()->toIso8601String(),
            );
        }

        if ($level === 'block') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        if ($level === 'throttle') {
            $retryAfter = RateLimiter::availableIn($limiterKey);

            return response()->json(
                ['message' => 'Too Many Requests'],
                429,
                ['Retry-After' => (string) $retryAfter]
            );
        }

        return $response;
    }
}
