import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
django.setup()

from myapp.threat_detector import ThreatDetector

urls = [
    'https://google.com',
    'https://www.google.com',
    'https://subdomain.mit.edu',
    'https://facebook.com/login',
    'https://secure.university.edu.au/path',
    'https://example.gov',
    'https://example.education',
    'https://trusted-site.edu',
    'https://www.microsoft.com:443/path',
    'https://untrusted.com/login?account=1'
]

det = ThreatDetector()
for u in urls:
    res = det.detect_phishing_url(u)
    print(u, '=>', res['is_phishing'], res['risk_level'], res['alerts'][:2])
