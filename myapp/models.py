from django.db import models
from django.contrib.auth.models import User

class Threat(models.Model):
    THREAT_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    file_name = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, unique=True)
    file_size = models.PositiveIntegerField()
    threat_level = models.CharField(max_length=10, choices=THREAT_LEVELS, default='LOW')
    confidence_score = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    scan_date = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    detection_details = models.JSONField(default=dict)
    is_quarantined = models.BooleanField(default=False)
    quarantine_path = models.CharField(max_length=500, blank=True)

    def __str__(self):
        return f"{self.file_name} - {self.threat_level}"

    class Meta:
        ordering = ['-scan_date']

class ScanLog(models.Model):
    SCAN_TYPES = [
        ('MALWARE', 'Malware Scan'),
        ('URL', 'URL Scan'),
        ('EMAIL', 'Email Scan'),
        ('SYSTEM', 'System Scan'),
    ]

    scan_type = models.CharField(max_length=10, choices=SCAN_TYPES)
    target = models.CharField(max_length=500)
    result = models.CharField(max_length=20, default='CLEAN')
    scan_time = models.DateTimeField(auto_now_add=True)
    duration = models.DurationField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.scan_type} - {self.target}"

    class Meta:
        ordering = ['-scan_time']

class ThreatLog(models.Model):
    THREAT_TYPES = [
        ('phishing', 'Phishing'),
        ('malware', 'Malware'),
        ('brute_force', 'Brute Force'),
        ('sql_injection', 'SQL Injection'),
        ('xss', 'XSS'),
        ('ransomware', 'Ransomware'),
        ('zero_day', 'Zero Day'),
    ]

    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    threat_type = models.CharField(max_length=50, choices=THREAT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='medium')
    status = models.CharField(max_length=20, default='detected')
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    url = models.URLField(null=True, blank=True)
    file_hash = models.CharField(max_length=128, null=True, blank=True)
    description = models.TextField()
    detection_method = models.CharField(max_length=100, default='Manual')
    confidence_score = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    reported_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

class ThreatIntelligence(models.Model):
    INDICATOR_TYPES = [
        ('URL', 'URL'),
        ('IP', 'IP Address'),
        ('DOMAIN', 'Domain'),
        ('HASH', 'File Hash'),
    ]

    indicator_type = models.CharField(max_length=10, choices=INDICATOR_TYPES)
    indicator_value = models.CharField(max_length=500)
    threat_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=10, choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')])
    description = models.TextField()
    source = models.CharField(max_length=100, default='Internal')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.indicator_type}: {self.indicator_value}"

    class Meta:
        ordering = ['-created_at']
        unique_together = ('indicator_type', 'indicator_value')

class LoginLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    login_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    session_id = models.CharField(max_length=40, blank=True)
    status = models.CharField(max_length=20, default='success')

    class Meta:
        ordering = ['-login_time']

class LogoutLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    logout_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    session_id = models.CharField(max_length=40, blank=True)
    status = models.CharField(max_length=20, default='success')

    class Meta:
        ordering = ['-logout_time']

class QuizLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    score = models.IntegerField()
    total_questions = models.IntegerField(default=10)
    percentage = models.DecimalField(max_digits=5, decimal_places=2)
    wrong_questions = models.JSONField(default=list)
    full_answers = models.JSONField(default=dict)
    resources = models.CharField(max_length=255, default="Security Awareness Quiz")

    def __str__(self):
        return f"Quiz {self.score}/{self.total_questions} - {self.user}"

    class Meta:
        ordering = ['-timestamp']
