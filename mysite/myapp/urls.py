from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('admin/register/', views.admin_register_view, name='admin_register'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('all-threats/', views.all_threats, name='all_threats'),
    path('scan-url/', views.scan_url, name='scan_url'),
    path('scan-email/', views.scan_email, name='scan_email'),
]
