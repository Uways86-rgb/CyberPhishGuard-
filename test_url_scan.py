import os
import sys
import django

# Add the project directory to sys.path
sys.path.append(os.path.join(os.getcwd(), 'mysite'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
django.setup()

from myapp.threat_detector import ThreatDetector
from myapp.models import ThreatLog, ThreatIntelligence
from django.contrib.auth.models import User

def test_url_scanning():
    print("Testing URL scanning functionality...")

    # Create a test user if not exists
    user, created = User.objects.get_or_create(username='testuser', defaults={'email': 'test@example.com'})
    if created:
        user.set_password('password123')
        user.save()
        print("Test user created.")

    # Test ThreatDetector
    detector = ThreatDetector()

    # Test safe URL
    safe_url = "https://www.google.com"
    result = detector.detect_phishing_url(safe_url)
    print(f"Safe URL result: {result}")

    # Test phishing URL
    phishing_url = "http://192.168.1.1/login.php"
    result = detector.detect_phishing_url(phishing_url)
    print(f"Phishing URL result: {result}")

    # Test logging threat
    if result['is_phishing']:
        threat_data = {
            'threat_type': 'phishing',
            'severity': 'high' if result['confidence_score'] >= 70 else 'medium',
            'source_ip': '127.0.0.1',
            'url': phishing_url,
            'description': f"Phishing URL detected: {', '.join(result['alerts'])}",
            'detection_method': 'URL Scanner',
            'confidence_score': result['confidence_score']
        }
        threat = detector.log_threat(threat_data, user)
        print(f"Threat logged: {threat.threat_type} - {threat.severity}")

    # Check if threat was logged
    threats = ThreatLog.objects.filter(url=phishing_url)
    print(f"Threats in database: {threats.count()}")

    print("URL scanning test completed successfully!")

if __name__ == "__main__":
    test_url_scanning()
