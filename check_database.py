#!/usr/bin/env python
"""
Simple script to check and view CyberPhishGuard database data
This script will work with any database configuration
"""

import os
import sys
import django
from datetime import datetime

# Add the project directory to sys.path
sys.path.append(os.path.join(os.getcwd(), 'mysite'))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')

try:
    django.setup()
    print("✅ Django setup successful!")
except Exception as e:
    print(f"❌ Django setup failed: {e}")
    print("Make sure you're running this from the CyberPhishGuard-/mysite/ directory")
    sys.exit(1)

# Import models
try:
    from myapp.models import QuizLog, ScanLog, ThreatLog, LoginLog, LogoutLog, ThreatIntelligence
    from django.contrib.auth.models import User
    from django.db import connection
    print("✅ Models imported successfully!")
except Exception as e:
    print(f"❌ Failed to import models: {e}")
    sys.exit(1)

def check_database_connection():
    """Check if database connection is working"""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            print(f"✅ Database connection: WORKING")
            return True
    except Exception as e:
        print(f"❌ Database connection: FAILED - {e}")
        return False

def get_table_info():
    """Get information about database tables"""
    try:
        from django.apps import apps
        from django.db import connection
        
        print("\n📊 DATABASE TABLES:")
        print("-" * 40)
        
        # Get all models
        models = apps.get_models()
        
        for model in models:
            table_name = model._meta.db_table
            try:
                count = model.objects.count()
                print(f"   📋 {table_name}: {count} records")
            except Exception as e:
                print(f"   ❌ {table_name}: Error ({e})")
                
    except Exception as e:
        print(f"❌ Failed to get table info: {e}")

def view_data_summary():
    """View summary of all data"""
    print(f"\n📈 DATA SUMMARY:")
    print("-" * 40)
    
    # User data
    try:
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        print(f"👥 Users: {total_users} total, {active_users} active")
    except Exception as e:
        print(f"❌ Users: Error - {e}")
    
    # Quiz data
    try:
        quiz_count = QuizLog.objects.count()
        print(f"📝 Quizzes: {quiz_count} total")
        if quiz_count > 0:
            latest_quiz = QuizLog.objects.latest('timestamp')
            print(f"   🕐 Latest: {latest_quiz.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(f"❌ Quizzes: Error - {e}")
    
    # Scan data
    try:
        scan_count = ScanLog.objects.count()
        print(f"🔍 Scans: {scan_count} total")
        if scan_count > 0:
            latest_scan = ScanLog.objects.latest('scan_time')
            print(f"   🕐 Latest: {latest_scan.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(f"❌ Scans: Error - {e}")
    
    # Threat data
    try:
        threat_count = ThreatLog.objects.count()
        print(f"⚠️  Threats: {threat_count} total")
        if threat_count > 0:
            latest_threat = ThreatLog.objects.latest('timestamp')
            print(f"   🕐 Latest: {latest_threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(f"❌ Threats: Error - {e}")

def view_sample_data():
    """View sample data from each table"""
    print(f"\n📋 SAMPLE DATA:")
    print("-" * 40)
    
    # Sample users
    try:
        users = User.objects.all()[:3]
        print(f"\n👥 Sample Users:")
        for user in users:
            print(f"   • {user.username} ({user.email}) - Active: {user.is_active}")
    except Exception as e:
        print(f"❌ Sample Users: Error - {e}")
    
    # Sample quiz results
    try:
        quizzes = QuizLog.objects.all().order_by('-timestamp')[:3]
        print(f"\n📝 Sample Quiz Results:")
        for quiz in quizzes:
            print(f"   • {quiz.user.username if quiz.user else 'Anonymous'}: {quiz.score}/{quiz.total_questions} ({quiz.percentage}%) - {quiz.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(f"❌ Sample Quizzes: Error - {e}")
    
    # Sample scan results
    try:
        scans = ScanLog.objects.all().order_by('-scan_time')[:3]
        print(f"\n🔍 Sample Scan Results:")
        for scan in scans:
            status = "✅" if scan.result == 'CLEAN' else "❌"
            print(f"   • {scan.scan_type}: {status} {scan.target[:30]}... - {scan.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(f"❌ Sample Scans: Error - {e}")

def main():
    print("=" * 60)
    print("  CyberPhishGuard Database Checker")
    print("=" * 60)
    print(f"Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check database connection
    if not check_database_connection():
        print("\n💡 TIPS:")
        print("1. Make sure your database server is running")
        print("2. Check your database settings in mysite/settings.py")
        print("3. Try running: python manage.py migrate")
        print("4. Try running: python manage.py createsuperuser")
        return
    
    # Get table information
    get_table_info()
    
    # View data summary
    view_data_summary()
    
    # View sample data
    view_sample_data()
    
    print("\n" + "=" * 60)
    print("  🎯 HOW TO VIEW YOUR DATA:")
    print("=" * 60)
    print("1. 🌐 WEB ADMIN: python manage.py runserver")
    print("   Visit: http://127.0.0.1:8000/admin/")
    print("   (Create superuser first: python manage.py createsuperuser)")
    print()
    print("2. 🖥️  COMMAND LINE: python manage.py view_data")
    print("   Options: --limit 10, --user username, --model quiz")
    print()
    print("3. 🐍 PYTHON SCRIPT: python view_database.py")
    print("   (Run from CyberPhishGuard-/mysite/ directory)")
    print()
    print("4. 📊 CSV FILES: Check uploads/quiz_results/ folder")
    print("   Contains detailed quiz results in Excel format")
    print()
    print("5. 🌐 WEB INTERFACE: http://127.0.0.1:8000/quiz-history/")
    print("   View your quiz history in the browser")

if __name__ == "__main__":
    main()