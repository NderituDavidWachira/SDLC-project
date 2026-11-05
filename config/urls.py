from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('audit/', include('audit.urls')),
    path('', include('scanner.urls')),
    path('', include('dashboard.urls')),
]
