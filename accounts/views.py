from django.conf import settings
from django.contrib.auth.views import LoginView
from django.core.cache import cache


def _key(request):
    username = request.POST.get('username', '').strip().lower()[:150]
    return f"login-fail:{request.META.get('REMOTE_ADDR', '')}:{username}"


class ThrottledLoginView(LoginView):
    """Login view that locks an IP+username pair after repeated failures."""

    template_name = 'registration/login.html'

    def post(self, request, *args, **kwargs):
        if cache.get(_key(request), 0) >= settings.LOGIN_MAX_ATTEMPTS:
            form = self.get_form()
            form.add_error(None, 'Too many failed attempts. Try again later.')
            return self.render_to_response(self.get_context_data(form=form), status=429)
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        key = _key(self.request)
        cache.set(key, cache.get(key, 0) + 1, settings.LOGIN_LOCKOUT_SECONDS)
        return super().form_invalid(form)

    def form_valid(self, form):
        cache.delete(_key(self.request))
        return super().form_valid(form)
