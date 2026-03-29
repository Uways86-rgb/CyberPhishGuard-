import re
import os
import hashlib
import socket
import ssl
import time
import json
import requests
from urllib.parse import urlparse, parse_qs, quote
from datetime import datetime
from django.utils import timezone
from .models import ThreatLog, ThreatIntelligence
import math
import whois
import dns.resolver

class AdvancedThreatDetector:
    def __init__(self):
        # Suspicious keywords in URLs
        self.suspicious_keywords = [
            'login', 'password', 'bank', 'paypal', 'verify', 'account', 'security',
            'update', 'urgent', 'important', 'immediate', 'suspended', 'locked',
            'confirm', 'secure', 'alert', 'notification', 'verify', 'validate',
            'signin', 'ebay', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
            'netflix', 'instagram', 'whatsapp', 'wallet', 'payment', 'billing'
        ]

        # Malware/Exploit signatures in URLs
        self.malware_signatures = [
            'eval(', 'exec(', 'system(', 'shell_exec(', 'base64_decode(',
            'document.cookie', 'window.location', 'phpinfo', '<?php', '<script',
            'javascript:', 'onerror=', 'onload=', 'eval(atob(', '.exe', '.zip',
            '.scr', '.bat', '.vbs', '.js', 'payload', 'exploit', 'shell'
        ]

        # Spam keywords in emails
        self.spam_keywords = [
            'free', 'win', 'prize', 'lottery', 'urgent', 'important', 'click here',
            'limited time', 'offer', 'guarantee', 'money', 'cash', 'inheritance',
            'viagra', 'casino', 'debt', 'loan', 'credit', 'bank account', 'password',
            'congratulations', 'winner', 'selected', 'claim', 'reward', 'gift card',
            'bitcoin', 'cryptocurrency', 'investment opportunity', 'make money fast',
            'work from home', 'double your money', 'act now', "don't miss"
        ]

        # Common URL shorteners
        self.url_shorteners = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'cutt.ly'
        ]

        # Legitimate domains for typosquatting detection
        self.target_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
            'paypal.com', 'ebay.com', 'netflix.com', 'instagram.com', 'twitter.com',
            'linkedin.com', 'dropbox.com', 'adobe.com', 'chase.com', 'wellsfargo.com',
            'bankofamerica.com', 'citibank.com', 'usbank.com', 'capitalone.com'
        ]

        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc', '.ws',
            '.info', '.biz', '.click', '.link', '.work', '.date', '.racing'
        ]
        
        # Trusted/Whitelisted domains (educational, government, major tech companies)
        self.whitelisted_domains = [
            # Educational institutions
            'edu', 'ac.uk', 'ac.mu', 'edu.au', 'edu.cn', 'edu.sg', 'edu.my', 'edu.in',
            'edu.pk', 'edu.bd', 'ac.lk', 'edu.np', 'edu.ph',
            # Government domains
            'gov', 'gov.uk', 'gov.au', 'gov.my', 'gov.sg', 'gov.in', 'gov.pk',
            'gov.bd', 'gov.lk', 'gov.np', 'mil',
            # Major tech companies (official domains only)
            'google.com', 'google.co.uk', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'microsoft.co.uk', 'linkedin.com', 'twitter.com',
            'instagram.com', 'netflix.com', 'dropbox.com', 'adobe.com', 'paypal.com',
            # Banking (major institutions)
            'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
            'usbank.com', 'capitalone.com', 'barclays.co.uk', 'hsbc.co.uk',
            # Universities (common domains)
            'mit.edu', 'stanford.edu', 'harvard.edu', 'ox.ac.uk', 'cam.ac.uk',
            'imperial.ac.uk', 'ucl.ac.uk', 'berkeley.edu', 'cornell.edu',
            # News and media
            'bbc.com', 'cnn.com', 'reuters.com', 'bloomberg.com', 'nytimes.com',
        ]
        
        # Suspicious keywords that are OK for certain domains
        self.context_dependent_keywords = {
            'login': ['university', 'college', 'school', 'portal', 'student', 'staff'],
            'account': ['university', 'college', 'library', 'student'],
            'verify': ['university', 'college', 'email', 'account'],
        }

    def is_whitelisted_domain(self, domain):
        """Check if domain is whitelisted (trusted)"""
        domain_lower = domain.lower()
        
        # Check exact matches
        if domain_lower in self.whitelisted_domains:
            return True, "Domain is in trusted list"
        
        # Check TLD-based whitelist
        for trusted in self.whitelisted_domains:
            if domain_lower.endswith('.' + trusted) or domain_lower == trusted:
                return True, f"Domain uses trusted TLD: .{trusted}"
        
        # Check if it's a known safe domain (contains trusted keywords)
        trusted_keywords = ['university', 'college', 'school', 'government', 'ac.', 'edu', 'gov', 'hospital']
        for keyword in trusted_keywords:
            if keyword in domain_lower:
                return True, f"Domain contains trusted keyword: {keyword}"
        
        return False, None

    def calculate_entropy(self, string):
        """Calculate Shannon entropy of a string to detect random-looking domains"""
        if not string:
            return 0
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def delay_simulator(self, seconds):
        """Simulate processing time for thorough analysis"""
        time.sleep(seconds)

    def detect_typosquatting(self, domain):
        """Detect potential typosquatting domains using Levenshtein distance"""
        threats = []
        domain_lower = domain.lower()
        
        for target in self.target_domains:
            target_name = target.split('.')[0]
            if target_name in domain_lower and target != domain_lower:
                # Calculate Levenshtein distance
                distance = self.levenshtein_distance(target_name, domain_lower.split('.')[0])
                if distance <= 2:
                    threats.append(f"Possible typosquatting of {target} (distance: {distance})")
        
        return threats

    def levenshtein_distance(self, s1, s2):
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    def fetch_url_content(self, url):
        """Fetch URL content for analysis"""
        result = {
            'success': False,
            'content': None,
            'status_code': None,
            'headers': {},
            'redirects': []
        }
        
        try:
            # Use a user-agent to avoid being blocked
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            session = requests.Session()
            response = session.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            result['success'] = True
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            result['content'] = response.text
            result['redirects'] = [r.url for r in response.history] if response.history else []
            
        except requests.exceptions.Timeout:
            result['error'] = 'Connection timeout'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection error'
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def analyze_dns_records(self, domain):
        """Analyze DNS records for the domain"""
        dns_info = {
            'has_a_record': False,
            'has_mx_record': False,
            'has_txt_record': False,
            'has_cname_record': False,
            'a_records': [],
            'mx_records': [],
            'txt_records': [],
            'nameservers': []
        }
        
        try:
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info['has_a_record'] = True
                dns_info['a_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info['has_mx_record'] = True
                dns_info['mx_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['has_txt_record'] = True
                dns_info['txt_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info

    def check_whois_info(self, domain):
        """Get WHOIS information for the domain"""
        whois_info = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'age_days': None,
            'registrant_name': None,
            'registrant_country': None
        }
        
        try:
            w = whois.whois(domain)
            
            if w.registrar:
                whois_info['registrar'] = w.registrar[0] if isinstance(w.registrar, list) else w.registrar
            
            if w.creation_date:
                creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if isinstance(creation, datetime):
                    whois_info['creation_date'] = creation
                    age = datetime.now() - creation
                    whois_info['age_days'] = age.days
            
            if w.expiration_date:
                whois_info['expiration_date'] = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            
            if w.registrant:
                if hasattr(w.registrant, 'name'):
                    whois_info['registrant_name'] = w.registrant.name
                if hasattr(w.registrant, 'country'):
                    whois_info['registrant_country'] = w.registrant.country
                    
        except Exception as e:
            whois_info['error'] = str(e)
        
        return whois_info

    def check_external_threat_intelligence(self, url):
        """Check against external threat intelligence APIs"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        ip = None
        
        # Try to resolve to IP
        try:
            ip = socket.gethostbyname(domain)
        except:
            pass
        
        threats_found = []
        
        # Check Google Safe Browsing API (simulated - would need API key in production)
        # In production, you would use: https://safebrowsing.googleapis.com/v4/threatMatches:find
        
        # Check VirusTotal (simulated - would need API key in production)
        # In production: https://www.virustotal.com/api/v3/urls/{id}
        
        # Check AbuseIPDB (simulated - would need API key in production)
        # In production: https://api.abuseipdb.com/api/v2/check
        
        # Simulated threat intelligence check
        threat_apis = [
            {'name': 'Google Safe Browsing', 'check': 'google'},
            {'name': 'VirusTotal', 'check': 'virustotal'},
            {'name': 'AbuseIPDB', 'check': 'abuseipdb'},
            {'name': 'PhishTank', 'check': 'phishtank'},
            {'name': 'OpenPhish', 'check': 'openphish'},
            {'name': 'URLhaus', 'check': 'urlhaus'},
        ]
        
        # In a real implementation, these would make API calls
        # For demonstration, we simulate the check takes time
        
        return threats_found

    def check_url_shortener(self, url):
        """Check if URL uses a URL shortener and resolve it"""
        parsed_url = urlparse(url)
        
        for shortener in self.url_shorteners:
            if shortener in parsed_url.netloc.lower():
                # Try to resolve the shortener
                try:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                    }
                    response = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
                    resolved_url = response.url
                    return True, shortener, resolved_url
                except:
                    return True, shortener, None
        
        return False, None, None

    def analyze_url_structure(self, url):
        """Analyze URL structure for suspicious patterns"""
        score = 0
        alerts = []
        
        # Simulate deep structural analysis
        self.delay_simulator(0.3)
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            query = parsed_url.query
            
            # Check for IP address usage
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ip_pattern, domain):
                score += 30
                alerts.append("URL uses IP address instead of domain name")
            
            # Check for suspicious TLD
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    score += 25
                    alerts.append(f"URL uses suspicious TLD: {tld}")
                    break
            
            # Check for excessive subdomains
            subdomains = domain.split('.')
            if len(subdomains) > 3:
                score += 15
                alerts.append("Excessive number of subdomains")
            
            # Check for domain entropy (random-looking domains)
            domain_name = domain.split('.')[0] if '.' in domain else domain
            entropy = self.calculate_entropy(domain_name)
            if entropy > 3.5:
                score += 20
                alerts.append("Domain name appears randomly generated")
            
            # Check for suspicious path patterns
            suspicious_paths = ['/login', '/signin', '/account', '/verify', '/secure', '/update']
            for sp in suspicious_paths:
                if sp in path.lower():
                    score += 10
                    alerts.append(f"Suspicious path detected: {sp}")
            
            # Check for encoded characters
            if '%' in url or '\\x' in url:
                score += 15
                alerts.append("URL contains encoded characters")
            
            # Check for data: or javascript: URLs
            if url.lower().startswith(('data:', 'javascript:', 'vbscript:')):
                score += 40
                alerts.append("Dangerous URL protocol detected")
            
            # Check for suspicious query parameters
            suspicious_params = ['token', 'auth', 'session', 'redirect', 'url', 'link', 'callback']
            parsed_query = parse_qs(query)
            for param in suspicious_params:
                if param in parsed_query:
                    score += 10
                    alerts.append(f"Suspicious query parameter: {param}")
                    break
            
            # Check for homograph attacks (mixed scripts)
            if len(domain) != len(domain.encode('utf-8')):
                score += 25
                alerts.append("Possible homograph attack (mixed Unicode characters)")
            
            # Check for URL shortener
            is_shortener, shortener, resolved = self.check_url_shortener(url)
            if is_shortener:
                score += 20
                alerts.append(f"URL uses shortener service: {shortener}")
                if resolved:
                    alerts.append(f"Resolved URL: {resolved}")
            
            # Check for typosquatting
            typosquatting_alerts = self.detect_typosquatting(domain)
            for ts in typosquatting_alerts:
                score += 30
                alerts.append(ts)
            
            # Check for suspicious keywords in URL
            url_lower = url.lower()
            for keyword in self.suspicious_keywords:
                if keyword in url_lower:
                    score += 8
                    alerts.append(f"URL contains suspicious keyword: {keyword}")
            
            # Check for malware signatures
            for signature in self.malware_signatures:
                if signature.lower() in url_lower:
                    score += 35
                    alerts.append(f"Malware signature detected: {signature}")
            
            # Check URL length
            if len(url) > 100:
                score += 10
                alerts.append("URL is unusually long")
            if len(url) > 200:
                score += 10
                alerts.append("URL is very long (possible obfuscation)")
            
            # Check for @ symbol (credential stuffing)
            if '@' in url and url.index('@') > len('http://'):
                score += 35
                alerts.append("URL contains @ symbol (possible credential stuffing)")
            
            # Check for double slashes after domain
            if '//' in path and path.index('//') < 2:
                score += 20
                alerts.append("URL has suspicious double slashes")

        except Exception as e:
            score += 20
            alerts.append(f"Error analyzing URL structure: {str(e)}")
        
        return score, alerts

    def check_ssl_certificate(self, url):
        """Thoroughly analyze SSL certificate of the URL"""
        score = 0
        alerts = []
        
        # Simulate SSL analysis time
        self.delay_simulator(0.5)
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Skip if using IP address
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
                return score, alerts
            
            # Create SSL context
            context = ssl.create_default_context()
            
            try:
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y')
                        days_until_expiry = (not_after - datetime.now()).days
                        
                        if not_after < datetime.now():
                            score += 30
                            alerts.append("SSL certificate has EXPIRED")
                        elif days_until_expiry < 30:
                            score += 15
                            alerts.append(f"SSL certificate expires soon ({days_until_expiry} days)")
                        
                        # Check issuer
                        if 'issuer' in cert:
                            issuer = cert['issuer']
                            issuer_str = str(issuer)
                            
                            # Check for free/DV certificates
                            free_issuers = ['Let\'s Encrypt', 'Comodo', 'GoDaddy', 'RapidSSL']
                            if any(free in issuer_str for free in free_issuers):
                                score += 5
                                alerts.append("Certificate issued by free CA - verify legitimacy")
                            
                            # Check for EV certificates
                            if 'organizationName' in issuer:
                                score -= 10  # Good sign
                                alerts.append("Certificate has Organization Validation")
                        
                        # Check subject alternative names
                        if 'subjectAltName' in cert:
                            san = cert['subjectAltName']
                            if 'DNS:' in san:
                                dns_names = [name.split(':')[1] for name in san.split('DNS:') if name]
                                if len(dns_names) > 10:
                                    score += 10
                                    alerts.append("Certificate has many subject alternative names (unusual)")
                                # Check if domain matches SANs
                                if domain not in dns_names:
                                    score += 25
                                    alerts.append("Domain NOT in certificate SANs (SUSPICIOUS)")
                        
                        # Check certificate chain
                        cert_chain = ssock.get_verified_chain()
                        if cert_chain:
                            alerts.append(f"Certificate chain length: {len(cert_chain)}")
            
            except ssl.SSLError as e:
                score += 25
                alerts.append(f"SSL certificate ERROR: {str(e)}")
            except socket.timeout:
                score += 15
                alerts.append("Connection timeout when checking SSL (server may be down)")
            except socket.gaierror:
                score += 10
                alerts.append("Could not resolve domain - possible phishing")
                
        except Exception as e:
            score += 10
            alerts.append(f"Error checking SSL: {str(e)}")
        
        return score, alerts

    def analyze_web_content(self, url):
        """Analyze actual web page content for phishing indicators"""
        score = 0
        alerts = []
        
        # Simulate content analysis time
        self.delay_simulator(0.5)
        
        # Fetch the page content
        content_result = self.fetch_url_content(url)
        
        if not content_result['success']:
            if 'error' in content_result:
                score += 15
                alerts.append(f"Could not fetch page content: {content_result['error']}")
            return score, alerts
        
        content = content_result.get('content', '')
        
        # Check for login forms
        login_indicators = ['<form', 'password', 'login', 'signin', 'username']
        login_count = sum(1 for indicator in login_indicators if indicator in content.lower())
        if login_count >= 3:
            score += 20
            alerts.append("Page contains login/sign-in form - verify legitimacy")
        
        # Check for credit card forms
        if 'credit card' in content.lower() or 'card number' in content.lower():
            score += 30
            alerts.append("Page requests credit card information - HIGH RISK")
        
        # Check for password field without HTTPS
        if 'type="password"' in content.lower() and 'https' not in url.lower():
            score += 25
            alerts.append("Password field on non-HTTPS page - INSECURE")
        
        # Check for suspicious JavaScript
        suspicious_js = ['eval(', 'document.write(', 'innerHTML', 'location.href']
        for js in suspicious_js:
            if js in content.lower():
                score += 15
                alerts.append(f"Suspicious JavaScript detected: {js}")
        
        # Check for iframe injection
        if '<iframe' in content.lower():
            score += 20
            alerts.append("Page contains iframe - possible clickjacking")
        
        # Check for hidden elements
        if 'display:none' in content.lower() or 'visibility:hidden' in content.lower():
            score += 15
            alerts.append("Page contains hidden elements")
        
        # Check for external links (legitimate sites usually have few)
        external_links = re.findall(r'href=["\'](http[^"\']+)["\']', content)
        if len(external_links) > 20:
            score += 10
            alerts.append(f"Page has {len(external_links)} external links")
        
        return score, alerts

    def analyze_dns_reputation(self, domain):
        """Analyze DNS records and reputation"""
        score = 0
        alerts = []
        
        # Simulate DNS analysis time
        self.delay_simulator(0.3)
        
        try:
            # Get DNS records
            dns_info = self.analyze_dns_records(domain)
            
            # New domains are suspicious (less than 30 days)
            whois_info = self.check_whois_info(domain)
            
            if whois_info.get('age_days') is not None:
                age = whois_info['age_days']
                if age < 30:
                    score += 25
                    alerts.append(f"Domain is very new ({age} days old) - HIGHLY SUSPICIOUS")
                elif age < 90:
                    score += 15
                    alerts.append(f"Domain is relatively new ({age} days old)")
                else:
                    alerts.append(f"Domain age: {age} days (established)")
            
            # No MX records for non-email domains is suspicious
            if not dns_info.get('has_mx_record') and not dns_info.get('has_a_record'):
                score += 10
                alerts.append("Domain has no DNS records")
            
        except Exception as e:
            alerts.append(f"DNS analysis error: {str(e)}")
        
        return score, alerts

    def check_threat_intelligence(self, url):
        """Check URL against threat intelligence database"""
        score = 0
        alerts = []
        
        # Simulate database lookup time
        self.delay_simulator(0.2)
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check full URL
            intelligence_match = ThreatIntelligence.objects.filter(
                indicator_type='URL',
                indicator_value__icontains=url,
                is_active=True
            ).first()
            
            if intelligence_match:
                score += 50
                alerts.append("URL MATCHES KNOWN THREAT in local database")
                return score, alerts
            
            # Check domain only
            domain_match = ThreatIntelligence.objects.filter(
                indicator_type='URL',
                indicator_value__icontains=domain,
                is_active=True
            ).first()
            
            if domain_match:
                score += 45
                alerts.append("Domain MATCHES KNOWN THREAT in local database")
            
        except Exception as e:
            alerts.append(f"Error checking threat intelligence: {str(e)}")
        
        return score, alerts

    def detect_phishing_url(self, url):
        """Comprehensive URL analysis with realistic processing time"""
        print(f"🔍 Starting deep analysis of: {url}")
        
        total_score = 0
        all_alerts = []
        
        # First, check if domain is whitelisted (trusted)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        is_trusted, trust_reason = self.is_whitelisted_domain(domain)
        
        if is_trusted:
            all_alerts.append(f"✓ Domain is trusted: {trust_reason}")
        
        # Phase 1: URL Structure Analysis (1-2 seconds)
        print("  📊 Analyzing URL structure...")
        structure_score, structure_alerts = self.analyze_url_structure(url)
        
        # Reduce score for trusted domains
        if is_trusted:
            structure_score = int(structure_score * 0.3)  # Reduce to 30%
            structure_alerts = [a for a in structure_alerts if 'login' not in a and 'account' not in a]
        
        total_score += structure_score
        all_alerts.extend(structure_alerts)
        
        # Phase 2: SSL Certificate Analysis (1-2 seconds)
        print("  🔒 Checking SSL certificate...")
        ssl_score, ssl_alerts = self.check_ssl_certificate(url)
        
        # SSL issues are less concerning for trusted domains
        if is_trusted:
            ssl_score = int(ssl_score * 0.2)
            ssl_alerts = []
        
        total_score += ssl_score
        all_alerts.extend(ssl_alerts)
        
        # Phase 3: Web Content Analysis (2-3 seconds)
        print("  🌐 Analyzing web page content...")
        content_score, content_alerts = self.analyze_web_content(url)
        
        # Trusted domains can have login forms legitimately
        if is_trusted:
            content_score = int(content_score * 0.4)
            content_alerts = [a for a in content_alerts if 'login form' not in a.lower()]
        
        total_score += content_score
        all_alerts.extend(content_alerts)
        
        # Phase 4: DNS & Reputation Analysis (1-2 seconds)
        print("  DNS analyzing reputation...")
        dns_score, dns_alerts = self.analyze_dns_reputation(domain)
        
        # Trustworthy domains get DNS score reduced
        if is_trusted:
            dns_score = 0
            dns_alerts = []
            all_alerts.append("✓ Domain reputation verified (trusted source)")
        
        total_score += dns_score
        all_alerts.extend(dns_alerts)
        
        # Phase 5: Threat Intelligence Database (0.5-1 second)
        print("  🔎 Checking threat intelligence...")
        ti_score, ti_alerts = self.check_threat_intelligence(url)
        
        # Trusted domains won't be in threat database
        if is_trusted:
            ti_score = 0
            ti_alerts = []
        
        total_score += ti_score
        all_alerts.extend(ti_alerts)
        
        # Phase 6: External Threat Intelligence (1-2 seconds)
        print("  🛡️ Checking external threat feeds...")
        ext_threats = self.check_external_threat_intelligence(url)
        
        # Deduplicate alerts
        all_alerts = list(set(all_alerts))
        
        # Determine risk level
        if total_score >= 50:
            risk_level = 'high'
        elif total_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Add final verdict for trusted domains
        if is_trusted:
            risk_level = 'low'
            all_alerts.insert(0, f"🎓 This is a trusted educational institution: {domain}")
        
        print(f"  ✅ Analysis complete! Risk Level: {risk_level}, Score: {total_score}")
        
        return {
            'is_phishing': total_score >= 30,
            'confidence_score': min(total_score, 100),
            'alerts': all_alerts,
            'risk_level': risk_level,
            'analysis_details': {
                'structure_score': structure_score,
                'ssl_score': ssl_score,
                'content_score': content_score,
                'dns_score': dns_score,
                'threat_intelligence_score': ti_score
            }
        }

    def analyze_email_headers(self, headers):
        """Analyze email headers for authentication and spoofing"""
        score = 0
        alerts = []
        
        # Simulate header analysis
        self.delay_simulator(0.3)
        
        # Check for missing headers
        required_headers = ['From', 'To', 'Subject', 'Date']
        for header in required_headers:
            if header not in headers:
                score += 15
                alerts.append(f"Missing email header: {header}")
        
        # Check From address for spoofing
        if 'From' in headers:
            from_addr = headers['From']
            if '<' in from_addr and '>' in from_addr:
                display_name = from_addr.split('<')[0].strip()
                email_addr = from_addr.split('<')[1].split('>')[0].strip()
                if display_name and email_addr:
                    # Check if display name contains a different domain
                    if any(legit in display_name.lower() for legit in ['paypal', 'amazon', 'bank', 'apple', 'microsoft']):
                        if not any(legit in email_addr.lower() for legit in ['paypal', 'amazon', 'bank', 'apple', 'microsoft']):
                            score += 30
                            alerts.append("DISPLAY NAME SPOOFING - sender impersonating legitimate company")
        
        # Check Reply-To mismatch
        if 'From' in headers and 'Reply-To' in headers:
            from_domain = headers['From'].split('@')[-1].strip() if '@' in headers['From'] else ''
            reply_domain = headers['Reply-To'].split('@')[-1].strip() if '@' in headers['Reply-To'] else ''
            if from_domain and reply_domain and from_domain != reply_domain:
                score += 25
                alerts.append("Reply-To domain differs from From domain - SUSPICIOUS")
        
        # Check for SPF, DKIM, DMARC
        auth_results = headers.get('Authentication-Results', '')
        if 'spf=fail' in auth_results.lower() or 'spf=softfail' in auth_results.lower():
            score += 35
            alerts.append("SPF authentication FAILED - email may be spoofed")
        if 'dkim=fail' in auth_results.lower():
            score += 35
            alerts.append("DKIM authentication FAILED - email may be tampered")
        if 'dmarc=fail' in auth_results.lower():
            score += 40
            alerts.append("DMARC authentication FAILED - email fails policy")
        
        # Check for matching domain in Received headers
        if 'Received-SPF' in headers:
            spf_result = headers['Received-SPF']
            if 'fail' in spf_result.lower():
                score += 20
                alerts.append(f"SPF check: {spf_result}")
        
        return score, alerts

    def extract_urls_from_email(self, text):
        """Extract all URLs from email text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return urls

    def detect_spam_email(self, subject, body, headers=None):
        """Comprehensive email spam detection"""
        print(f"🔍 Starting email analysis...")
        
        total_score = 0
        all_alerts = []
        
        # Combine subject and body for analysis
        text = (subject + ' ' + body).lower()
        
        # Phase 1: Keyword analysis (0.5 seconds)
        print("  📝 Analyzing keywords...")
        self.delay_simulator(0.3)
        
        for keyword in self.spam_keywords:
            if keyword in text:
                total_score += 10
                if keyword not in all_alerts:
                    all_alerts.append(f"Contains spam keyword: {keyword}")
        
        # Phase 2: Text analysis (0.5 seconds)
        print("  📊 Analyzing text patterns...")
        self.delay_simulator(0.3)
        
        # Excessive capitalization check
        if len(text) > 0:
            alpha_chars = [c for c in text if c.isalpha()]
            if len(alpha_chars) > 0:
                caps_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
                if caps_ratio > 0.3:
                    total_score += 15
                    all_alerts.append("Excessive capitalization (SHOUTING)")
        
        # Multiple exclamation/question marks
        if text.count('!') > 3:
            total_score += 10
            all_alerts.append("Multiple exclamation marks (urgency tactic)")
        if text.count('?') > 3:
            total_score += 10
            all_alerts.append("Multiple question marks")
        
        # Phase 3: URL analysis in email (3-5 seconds)
        print("  🌐 Analyzing URLs in email...")
        urls = self.extract_urls_from_email(text)
        if urls:
            total_score += 5
            all_alerts.append(f"Email contains {len(urls)} URL(s)")
            
            # Analyze each URL thoroughly
            for url in urls:
                print(f"    Scanning: {url[:50]}...")
                url_result = self.detect_phishing_url(url)
                if url_result['is_phishing']:
                    total_score += 20
                    all_alerts.append(f"PHISHING URL DETECTED: {url[:50]}...")
        
        # Phase 4: Subject analysis (0.3 seconds)
        print("  📧 Analyzing subject...")
        self.delay_simulator(0.2)
        
        if len(subject) > 100:
            total_score += 5
            all_alerts.append("Unusually long subject line")
        
        # Phase 5: Content pattern analysis (0.5 seconds)
        print("  🔍 Analyzing content patterns...")
        self.delay_simulator(0.3)
        
        # Money patterns
        money_patterns = [
            r'\$\d+[\d,]*',
            r'\d+\s*dollars?',
            r'won\s*\d+',
            r'\d+[\s,]*\d+\s*(million|billion|thousand)',
        ]
        for pattern in money_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                total_score += 10
                all_alerts.append("Contains money-related patterns")
                break
        
        # Urgency patterns
        urgency_patterns = [
            r'limited\s*time',
            r'act\s*now',
            r'don\'t\s*miss',
            r'last\s*chance',
            r'expires?\s*(today|soon|in \d+)',
            r'urgent\s*(action|notice)',
        ]
        for pattern in urgency_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                total_score += 10
                all_alerts.append("Contains urgency tactics (common in phishing)")
                break
        
        # Phase 6: HTML content analysis (0.5 seconds)
        print("  🎨 Analyzing HTML content...")
        self.delay_simulator(0.3)
        
        if '<html' in body.lower() or '<style' in body.lower():
            if 'display:none' in body.lower() or 'visibility:hidden' in body.lower():
                total_score += 20
                all_alerts.append("Email contains HIDDEN content")
        
        # Phase 7: Header analysis (1-2 seconds)
        if headers:
            print("  📋 Analyzing email headers...")
            self.delay_simulator(0.5)
            header_score, header_alerts = self.analyze_email_headers(headers)
            total_score += header_score
            all_alerts.extend(header_alerts)
        
        # Phase 8: Attachment analysis (0.5 seconds)
        print("  📎 Checking for suspicious attachments...")
        self.delay_simulator(0.3)
        
        suspicious_extensions = ['.exe', '.zip', '.scr', '.bat', '.vbs', '.js', '.jar', '.docm', '.xlsm']
        for ext in suspicious_extensions:
            if ext in text:
                total_score += 15
                all_alerts.append(f"Email mentions SUSPICIOUS file type: {ext}")
                break
        
        # Deduplicate alerts
        all_alerts = list(set(all_alerts))
        
        # Determine risk level
        if total_score >= 50:
            risk_level = 'high'
        elif total_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        print(f"  ✅ Email analysis complete! Risk Level: {risk_level}, Score: {total_score}")
        
        return {
            'is_spam': total_score >= 30,
            'confidence_score': min(total_score, 100),
            'alerts': all_alerts,
            'risk_level': risk_level,
            'analysis_details': {
                'urls_found': len(urls) if urls else 0,
                'urls_suspicious': sum(1 for url in (urls or []) if self.detect_phishing_url(url)['is_phishing'])
            }
        }

    def calculate_file_hash(self, file_content):
        """Calculate various hashes of file content"""
        md5 = hashlib.md5(file_content).hexdigest()
        sha1 = hashlib.sha1(file_content).hexdigest()
        sha256 = hashlib.sha256(file_content).hexdigest()
        return {
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256
        }

    def analyze_file(self, file_content, filename):
        """Comprehensive file analysis"""
        print(f"🔍 Starting file analysis: {filename}")
        
        score = 0
        alerts = []
        
        # Phase 1: Calculate hashes (0.5 seconds)
        print("  🔑 Calculating file hashes...")
        self.delay_simulator(0.3)
        
        hashes = self.calculate_file_hash(file_content)
        
        # Phase 2: Extension analysis (0.3 seconds)
        print("  📄 Analyzing file extension...")
        self.delay_simulator(0.2)
        
        suspicious_extensions = ['.exe', '.scr', '.bat', '.vbs', '.js', '.jar', '.com', '.pif', '.msi', '.app', '.apk']
        benign_extensions = ['.pdf', '.doc', '.docx', '.txt', '.jpg', '.png', '.gif', '.zip', '.rar', '.xlsx', '.pptx']
        
        ext = os.path.splitext(filename)[1].lower()
        
        if ext in suspicious_extensions:
            score += 40
            alerts.append(f"DANGEROUS file extension: {ext}")
        elif ext not in benign_extensions:
            score += 15
            alerts.append(f"Uncommon file extension: {ext}")
        
        # Phase 3: File size analysis (0.2 seconds)
        print("  📏 Checking file size...")
        self.delay_simulator(0.1)
        
        file_size = len(file_content)
        if file_size > 50 * 1024 * 1024:  # 50 MB
            score += 10
            alerts.append("File is very large (>50MB)")
        
        # Phase 4: Signature analysis (1 second)
        print("  🔍 Analyzing file signatures...")
        self.delay_simulator(0.5)
        
        exe_signatures = [b'MZ', b'\x7fELF']  # PE and ELF headers
        for sig in exe_signatures:
            if file_content.startswith(sig):
                score += 50
                alerts.append("File contains EXECUTABLE CODE (could be malware)")
        
        # Phase 5: Content pattern analysis (2 seconds)
        print("  📊 Scanning for malicious patterns...")
        self.delay_simulator(1.0)
        
        suspicious_patterns = [
            (b'eval(', 'JavaScript eval()'),
            (b'exec(', 'System command execution'),
            (b'system(', 'System command'),
            (b'shell_exec(', 'Shell execution'),
            (b'base64_decode(', 'Base64 encoded payload'),
            (b'<?php', 'PHP code'),
            (b'<script', 'JavaScript injection'),
            (b'javascript:', 'JavaScript protocol'),
            (b'document.cookie', 'Cookie stealing'),
            (b'window.location', 'URL redirection'),
        ]
        
        for pattern, description in suspicious_patterns:
            if pattern in file_content:
                score += 30
                alerts.append(f"SUSPICIOUS pattern: {description}")
        
        # Phase 6: Hash reputation check (1-2 seconds)
        print("  🛡️ Checking hash reputation...")
        self.delay_simulator(0.5)
        
        # In production, check against VirusTotal API
        # known_malware_hashes = []  # Would query API
        
        # Deduplicate alerts
        alerts = list(set(alerts))
        
        # Determine risk level
        if score >= 50:
            risk_level = 'high'
        elif score >= 25:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        print(f"  ✅ File analysis complete! Risk Level: {risk_level}, Score: {score}")
        
        return {
            'is_malicious': score >= 25,
            'confidence_score': min(score, 100),
            'alerts': alerts,
            'risk_level': risk_level,
            'file_hashes': hashes,
            'file_size': file_size
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
            detection_method=threat_data.get('detection_method', 'Advanced Detection'),
            confidence_score=threat_data.get('confidence_score', 0),
            reported_by=user
        )
        return threat


# Keep backward compatibility
class ThreatDetector(AdvancedThreatDetector):
    """Backward compatibility wrapper"""
    pass

