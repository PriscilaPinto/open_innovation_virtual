<?php

namespace GuzzleHttp\VirtualPatch;

use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class VirtualPatch
{
    /**
     * Creates a middleware that validates Set-Cookie headers to mitigate CVE-2022-29248.
     * This middleware ensures that cookies set by a server are only for the request's host
     * or a valid superdomain, preventing malicious servers from setting cookies for unrelated domains.
     *
     * @return callable
     */
    public static function createCookieValidatorMiddleware(): callable
    {
        return function (callable $handler) {
            return function (RequestInterface $request, array $options) use ($handler) {
                return $handler($request, $options)->then(
                    function (ResponseInterface $response) use ($request) {
                        $newResponse = $response;
                        $requestHost = $request->getUri()->getHost();
                        $setCookieHeaders = $response->getHeader('Set-Cookie');
                        $validSetCookieHeaders = [];

                        foreach ($setCookieHeaders as $cookieString) {
                            $cookieParts = self::parseCookieString($cookieString);
                            $cookieDomain = $cookieParts['domain'] ?? null;

                            if (self::isValidCookieDomain($cookieDomain, $requestHost)) {
                                $validSetCookieHeaders[] = $cookieString;
                            }
                            // Invalid cookies are silently dropped by not adding them to validSetCookieHeaders
                        }

                        // Replace the Set-Cookie header with only the valid ones
                        return $newResponse->withHeader('Set-Cookie', $validSetCookieHeaders);
                    }
                );
            };
        };
    }

    /**
     * Parses a Set-Cookie string into an associative array of key-value pairs.
     *
     * @param string $cookieString
     * @return array
     */
    private static function parseCookieString(string $cookieString): array
    {
        $parts = explode(';', $cookieString);
        $cookie = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if (strpos($part, '=') !== false) {
                list($key, $value) = explode('=', $part, 2);
                $cookie[strtolower($key)] = $value;
            } else {
                $cookie[strtolower($part)] = true; // e.g., 'HttpOnly'
            }
        }
        return $cookie;
    }

    /**
     * Validates if a cookie domain is permissible for a given request host according to RFC 6265.
     *
     * @param string|null $cookieDomain The domain specified in the Set-Cookie header.
     * @param string $requestHost The host of the request URI.
     * @return bool
     */
    private static function isValidCookieDomain(?string $cookieDomain, string $requestHost): bool
    {
        if (empty($cookieDomain)) {
            return true; // If no domain is specified, it defaults to the request host, which is valid.
        }

        $cookieDomain = strtolower(ltrim($cookieDomain, '.')); // Remove leading dot if present
        $requestHost = strtolower($requestHost);

        // The cookie domain must be identical to the request host, or a superdomain of it.
        // E.g., requestHost = "sub.example.com", cookieDomain = "example.com" (valid)
        // E.g., requestHost = "example.com", cookieDomain = "example.com" (valid)
        // E.g., requestHost = "example.com", cookieDomain = "sub.example.com" (invalid)

        // If the domains are identical, it's valid.
        if ($requestHost === $cookieDomain) {
            return true;
        }

        // Check if the request host is a subdomain of the cookie domain.
        // This means requestHost must end with "." + cookieDomain.
        // Using PHP 7.x compatible `str_ends_with` equivalent:
        if (substr($requestHost, -strlen('.' . $cookieDomain)) === '.' . $cookieDomain) {
            return true;
        }

        return false;
    }

    /**
     * Applies virtual patches to a Guzzle HandlerStack.
     * This function should be called after creating the HandlerStack but before creating the Guzzle Client.
     *
     * @param HandlerStack $stack The Guzzle HandlerStack to patch.
     */
    public static function applyGuzzleVirtualPatches(HandlerStack $stack): void
    {
        // Mitigation for CVE-2022-29248: Add cookie domain validation middleware.
        // This middleware runs *before* Guzzle's default cookie middleware (if present)
        // to filter out invalid Set-Cookie headers received from responses.
        if ($stack->has('cookies')) {
            $stack->before('cookies', self::createCookieValidatorMiddleware(), 'virtual_patch_cookie_validator');
        } else {
            // If no 'cookies' middleware is present, just push our validator.
            $stack->push(self::createCookieValidatorMiddleware(), 'virtual_patch_cookie_validator');
        }

        // Mitigation for CVE-2022-31042, CVE-2022-31043, CVE-2022-31090, CVE-2022-31091:
        // These vulnerabilities are related to Guzzle's default redirect middleware
        // forwarding sensitive headers (Cookie, Authorization) insecurely during redirects
        // (e.g., HTTPS to HTTP downgrade, cross-origin, or port change).
        // The recommended workaround for these issues is to disable redirects if not strictly required.
        // For an autonomous virtual patch that does not alter original libraries and avoids
        // complex replication of Guzzle's internal redirect logic, disabling the problematic
        // default redirect middleware is the most robust and safest approach.
        if ($stack->has('redirect')) {
            $stack->remove('redirect');
        }
    }
}