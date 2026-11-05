from django.urls import path

from . import views

urlpatterns = [
    path('scan/', views.RunScanView.as_view(), name='run-scan'),
    path('finding/<int:pk>/status/', views.FindingStatusView.as_view(), name='finding-status'),
]
