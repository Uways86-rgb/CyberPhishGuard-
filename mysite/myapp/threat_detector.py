import re
import os
import hashlib
from urllib.parse import urlparse
from django.utils import timezone
from .models import ThreatLog, ThreatIntelligence

class ThreatDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'password', 'bank', 'paypal', 'verify', 'account', 'security',
            'update', 'urgent', 'important', 'immediate', 'suspended', 'locked'
        ]

        self.malware_signatures = [
            'eval(', 'exec(', 'system(', 'shell_exec(', 'base64_decode(',
            'document.cookie', 'window.location', 'phpinfo'
        ]

        self.spam_keywords = [
            'free', 'win', 'prize', 'lottery', 'urgent', 'important', 'click here',
            'limited time', 'offer', 'guarantee', 'money', 'cash', 'inheritance',
            'viagra', 'casino', 'debt', 'loan', 'credit', 'bank account', 'password'
        ]

    def detect_phishing_url(self, url):
        """Detect potential phishing URLs"""
        score = 0
        alerts = []

        try:
            parsed_url = urlparse(url)

            # Check for IP address instead of domain
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed_url.netloc):
                score += 30
                alerts.append("URL uses IP address instead of domain name")

            # Check for suspicious characters in domain
            if re.search(r'[-\d]{5,}', parsed_url.netloc):
                score += 20
                alerts.append("Domain contains suspicious character patterns")

            # Check URL length
            if len(url) > 75:
                score += 15
                alerts.append("URL is unusually long")

            # Check for suspicious keywords in path
            path_lower = parsed_url.path.lower()
            for keyword in self.suspicious_keywords:
                if keyword in path_lower:
                    score += 10
                    alerts.append(f"URL contains suspicious keyword: {keyword}")

            # Check against threat intelligence
            intelligence_match = ThreatIntelligence.objects.filter(
                indicator_type='URL',
                indicator_value__icontains=parsed_url.netloc,
                is_active=True
            ).first()

            if intelligence_match:
                score += 50
                alerts.append("URL matches known threat intelligence")

        except Exception as e:
            score = 100
            alerts.append(f"Error analyzing URL: {str(e)}")

        return {
            'is_phishing': score >= 30,
            'confidence_score': min(score, 100),
            'alerts': alerts,
            'risk_level': 'high' if score >= 50 else 'medium' if score >= 30 else 'low'
        }

    def log_threat(self, threat_data, user=None):
        """Log detected threat to database"""
        threat = ThreatLog.objects.create(
            threat_type=threat_data.get('threat_type'),
            severity=threat_data.get('severity', 'medium'),
            status='detected',
            source_ip=threat_data.get('source_ip'),
            target_ip=threat_data.get('target_ip'),
            url=threat_data.get('url'),
            file_hash=threat_data.get('file_hash'),
            description=threat_data.get('description', 'Automatically detected threat'),
            detection_method=threat_data.get('detection_method', 'AI Detection'),
            confidence_score=threat_data.get('confidence_score', 0),
            reported_by=user
        )
        return threat

    def detect_spam_email(self, subject, body):
        """Detect potential spam emails"""
        score = 0
        alerts = []

        # Combine subject and body for analysis
        text = (subject + ' ' + body).lower()

        # Check for spam keywords
        for keyword in self.spam_keywords:
            if keyword in text:
                score += 10
                alerts.append(f"Contains spam keyword: {keyword}")

        # Check for excessive capitalization
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        if caps_ratio > 0.3:
            score += 15
            alerts.append("Excessive capitalization detected")

        # Check for multiple exclamation marks
        if text.count('!') > 3:
            score += 10
            alerts.append("Multiple exclamation marks")

        # Check for suspicious links (basic check)
        if 'http' in text or 'www.' in text:
            score += 5
            alerts.append("Contains links")

        # Check subject length
        if len(subject) > 100:
            score += 5
            alerts.append("Unusually long subject")

        return {
            'is_spam': score >= 30,
            'confidence_score': min(score, 100),
            'alerts': alerts,
            'risk_level': 'high' if score >= 50 else 'medium' if score >= 30 else 'low'
        }
