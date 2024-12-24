from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.contrib import messages

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            last_activity = request.session.get('last_activity')
            if last_activity:
                last_activity = timezone.datetime.fromisoformat(last_activity)
                if timezone.now() > last_activity + timedelta(seconds=settings.SESSION_COOKIE_AGE):
                    logout(request)
                    request.session.flush()
                    messages.warning(request, "Session expired. Please login again.")
                    return redirect('login')
            
            request.session['last_activity'] = str(timezone.now())

        return self.get_response(request)





