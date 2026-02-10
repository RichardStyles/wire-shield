<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use RichardStyles\WireShield\Concerns\ScansPayloads;
use Symfony\Component\HttpFoundation\Response;

class ValidateLivewirePayloadSize
{
    use ScansPayloads;

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('wire-shield.enforce_payload_size', false) || ! $this->isLivewireRequest($request)) {
            return $next($request);
        }

        $maxBytes = config('wire-shield.max_payload_bytes', 1048576);
        $bodySize = strlen($request->getContent());

        if ($bodySize > $maxBytes) {
            return response()->json(['message' => 'Payload Too Large'], 413);
        }

        return $next($request);
    }
}
