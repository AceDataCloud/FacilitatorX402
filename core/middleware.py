from django.http import JsonResponse

from core.views import build_well_known_x402_data


class WellKnownX402Middleware:
    """Serve /.well-known/x402 even if URL resolution for dot-prefixed paths fails."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path in {"/.well-known/x402", "/.well-known/x402/"}:
            facilitator_url = request.build_absolute_uri("/").rstrip("/")
            return JsonResponse(build_well_known_x402_data(facilitator_url))

        return self.get_response(request)
