#!/usr/bin/env python
"""
Simple script to view CyberPhishGuard database data
Run this from the CyberPhishGuard-/mysite/ directory
"""

import os
import sys
import django
from datetime import datetime

# Add the project directory to sys.path
sys.path.append(os.path.join(os.getcwd(), 'mysite'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
django.setup()

from myapp.models import QuizLog, ScanLog, ThreatLog, LoginLog, LogoutLog, ThreatIntelligence
from django.contrib.auth.models import User

def print_separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_subheader(title):
    print(f"\n{'-'*40}")
    print(f"  {title}")
    print(f"{'-'*40}")

def view_quiz_data():
    print_subheader("QUIZ LOGS")
    quizzes = QuizLog.objects.all().order_by('-timestamp')[:10]
    
    if not quizzes:
        print("No quiz records found.")
        return
    
    for quiz in quizzes:
        print(f"\n📝 Quiz ID: {quiz.id}")
        print(f"   User: {quiz.user.username if quiz.user else 'Anonymous'}")
        print(f"   Score: {quiz.score}/{quiz.total_questions} ({quiz.percentage}%)")
        print(f"   Date: {quiz.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Wrong Questions: {len(quiz.wrong_questions)}")
        if quiz.wrong_questions:
            print(f"   Wrong: {', '.join(quiz.wrong_questions[:3])}...")
        print(f"   Answers: {len(quiz.full_answers)} questions answered")

def view_scan_data():
    print_subheader("SCAN LOGS")
    scans = ScanLog.objects.all().order_by('-scan_time')[:10]
    
    if not scans:
        print("No scan records found.")
        return
    
    for scan in scans:
        status = "✅ CLEAN" if scan.result == 'CLEAN' else "❌ THREAT"
        print(f"\n🔍 Scan ID: {scan.id}")
        print(f"   Type: {scan.scan_type}")
        print(f"   Target: {scan.target[:50]}...")
        print(f"   Result: {status}")
        print(f"   User: {scan.user.username if scan.user else 'Anonymous'}")
        print(f"   Date: {scan.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")

def view_threat_data():
    print_subheader("THREAT LOGS")
    threats = ThreatLog.objects.all().order_by('-timestamp')[:10]
    
    if not threats:
        print("No threat records found.")
        return
    
    for threat in threats:
        print(f"\n⚠️  Threat ID: {threat.id}")
        print(f"   Type: {threat.threat_type}")
        print(f"   Severity: {threat.severity.upper()}")
        print(f"   Status: {threat.status}")
        print(f"   Description: {threat.description[:60]}...")
        print(f"   User: {threat.reported_by.username if threat.reported_by else 'System'}")
        print(f"   Date: {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

def view_user_data():
    print_subheader("USER STATISTICS")
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    staff_users = User.objects.filter(is_staff=True).count()
    superusers = User.objects.filter(is_superuser=True).count()
    
    print(f"📊 Total Users: {total_users}")
    print(f"✅ Active Users: {active_users}")
    print(f"👔 Staff Users: {staff_users}")
    print(f"👑 Superusers: {superusers}")
    
    # Recent users
    recent_users = User.objects.order_by('-date_joined')[:5]
    if recent_users:
        print(f"\n🆕 Recent Users:")
        for user in recent_users:
            print(f"   • {user.username} ({user.email}) - {user.date_joined.strftime('%Y-%m-%d')}")

def view_login_logout_data():
    print_subheader("LOGIN/LOGOUT LOGS")
    
    # Login logs
    logins = LoginLog.objects.all().order_by('-login_time')[:5]
    print(f"\n🔐 Recent Logins:")
    for login in logins:
        status = "✅ SUCCESS" if login.status == 'success' else "❌ FAILED"
        print(f"   • {login.user.username} - {status} - {login.login_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Logout logs
    logouts = LogoutLog.objects.all().order_by('-logout_time')[:5]
    print(f"\n🚪 Recent Logouts:")
    for logout in logouts:
        status = "✅ SUCCESS" if logout.status == 'success' else "❌ FAILED"
        print(f"   • {logout.user.username} - {status} - {logout.logout_time.strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    print_separator("CyberPhishGuard Database Viewer")
    print(f"Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        view_user_data()
        view_quiz_data()
        view_scan_data()
        view_threat_data()
        view_login_logout_data()
        
        print_separator("Database View Complete")
        print("To view specific data, use Django management commands:")
        print("  python manage.py view_data quiz --limit 5")
        print("  python manage.py view_data scan --user username")
        print("  python manage.py view_data all")
        
    except Exception as e:
        print(f"Error viewing database: {e}")
        print("Make sure you're running this from the CyberPhishGuard-/mysite/ directory")

if __name__ == "__main__":
    main()