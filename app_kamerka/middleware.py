class SecurityHeadersMiddleware:
    """Attach baseline response security headers."""

    # MapLibre 3D map needs OpenFreeMap tiles + web workers; Leaflet map uses https: tiles.
    _CSP = (
        "default-src 'self'; "
        "img-src 'self' data: blob: https:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "worker-src 'self' blob:; "
        "child-src 'self' blob:; "
        "connect-src 'self' https://tiles.openfreemap.org https://*.openfreemap.org "
        "https://api.mapbox.com https://*.tiles.mapbox.com https://events.mapbox.com; "
        "frame-ancestors 'none';"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", self._CSP)
        response.setdefault("Referrer-Policy", "same-origin")
        response.setdefault("X-Content-Type-Options", "nosniff")
        return response
