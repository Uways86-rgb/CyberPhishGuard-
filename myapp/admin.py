from django.contrib import admin
from .models import ThreatLog, ScanLog, ThreatIntelligence, QuizLog, LoginLog, LogoutLog

@admin.register(QuizLog)
class QuizLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'score', 'total_questions', 'percentage', 'timestamp']
    list_filter = ['timestamp', 'score', 'percentage']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['timestamp']
    ordering = ['-timestamp']

@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ['scan_type', 'target', 'result', 'scan_time', 'user']
    list_filter = ['scan_type', 'result', 'scan_time']
    search_fields = ['target', 'user__username']
    readonly_fields = ['scan_time']
    ordering = ['-scan_time']

@admin.register(ThreatLog)
class ThreatLogAdmin(admin.ModelAdmin):
    list_display = ['threat_type', 'severity', 'status', 'timestamp', 'reported_by']
    list_filter = ['threat_type', 'severity', 'status', 'timestamp']
    search_fields = ['description', 'reported_by__username']
    readonly_fields = ['timestamp']
    ordering = ['-timestamp']

@admin.register(ThreatIntelligence)
class ThreatIntelligenceAdmin(admin.ModelAdmin):
    list_display = ['indicator_type', 'indicator_value', 'threat_type', 'severity', 'created_at']
    list_filter = ['indicator_type', 'threat_type', 'severity', 'created_at']
    search_fields = ['indicator_value']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']

@admin.register(LoginLog)
class LoginLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'login_time', 'ip_address', 'status']
    list_filter = ['status', 'login_time']
    search_fields = ['user__username', 'ip_address']
    readonly_fields = ['login_time']
    ordering = ['-login_time']

@admin.register(LogoutLog)
class LogoutLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'logout_time', 'ip_address', 'status']
    list_filter = ['status', 'logout_time']
    search_fields = ['user__username', 'ip_address']
    readonly_fields = ['logout_time']
    ordering = ['-logout_time']