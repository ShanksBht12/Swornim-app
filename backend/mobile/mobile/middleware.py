# Create this file: mobile/middleware.py
from django.utils.deprecation import MiddlewareMixin

class CSRFExemptAPIMiddleware(MiddlewareMixin):
    """
    Middleware to exempt API endpoints from CSRF validation
    while keeping CSRF protection for Django admin
    """
    def process_request(self, request):
        # Exempt all API endpoints from CSRF checks
        if request.path.startswith('/api/'):
            setattr(request, '_dont_enforce_csrf_checks', True)