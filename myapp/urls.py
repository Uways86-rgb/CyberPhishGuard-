from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('user-breakdown/', views.user_breakdown, name='user_breakdown'),
    path('logout-logs/', views.logout_logs, name='logout_logs'),
    path('admin-register/', views.admin_register_view, name='admin_register'),
    path('user-management/', views.user_management, name='user_management'),
    path('all-threats/', views.all_threats, name='all_threats'),
    path('scan-breakdown/', views.scan_breakdown, name='scan_breakdown'),
    path('threat-breakdown/', views.threat_breakdown, name='threat_breakdown'),
    path('threat-dashboard/', views.threat_dashboard, name='threat_dashboard'),
    path('malware/', views.malware_detection, name='malware'),
    path('malware-visualization/', views.malware_visualization, name='malware_visualization'),
    path('quiz/', views.quiz_awareness, name='quiz'),
    path('quiz-export/', views.quiz_csv_export, name='quiz_csv_export'),
    path('quiz-history/', views.quiz_history, name='quiz_history'),
    path('resources/', views.resources, name='resources'),
    path('scan-url/', views.scan_url, name='scan_url'),
    path('scan-email/', views.scan_email, name='scan_email'),
    path('superuser-dashboard/', views.superuser_dashboard, name='superuser_dashboard'),
]
