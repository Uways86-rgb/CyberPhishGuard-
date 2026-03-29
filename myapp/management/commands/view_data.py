from django.core.management.base import BaseCommand
from myapp.models import QuizLog, ScanLog, ThreatLog, LoginLog, LogoutLog
from django.contrib.auth.models import User
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'View data from CyberPhishGuard database'

    def add_arguments(self, parser):
        parser.add_argument('model', nargs='?', default='all', 
                          choices=['all', 'quiz', 'scan', 'threat', 'login', 'logout', 'users'],
                          help='Which model to view data from')
        parser.add_argument('--limit', type=int, default=10,
                          help='Number of records to display (default: 10)')
        parser.add_argument('--user', type=str, help='Filter by username')

    def handle(self, *args, **options):
        model = options['model']
        limit = options['limit']
        username = options['user']

        self.stdout.write(self.style.SUCCESS(f'\n=== CyberPhishGuard Database Viewer ===\n'))
        self.stdout.write(f'Model: {model.upper()}')
        self.stdout.write(f'Limit: {limit}')
        if username:
            self.stdout.write(f'User Filter: {username}')
        self.stdout.write('-' * 50)

        if model == 'all' or model == 'quiz':
            self.view_quiz_data(limit, username)
        
        if model == 'all' or model == 'scan':
            self.view_scan_data(limit, username)
        
        if model == 'all' or model == 'threat':
            self.view_threat_data(limit)
        
        if model == 'all' or model == 'login':
            self.view_login_data(limit, username)
        
        if model == 'all' or model == 'logout':
            self.view_logout_data(limit, username)
        
        if model == 'all' or model == 'users':
            self.view_users_data()

    def view_quiz_data(self, limit, username=None):
        self.stdout.write('\n📊 QUIZ LOGS:')
        self.stdout.write('-' * 30)
        
        queryset = QuizLog.objects.all().order_by('-timestamp')
        if username:
            queryset = queryset.filter(user__username=username)
        
        quizzes = queryset[:limit]
        
        if not quizzes:
            self.stdout.write(self.style.WARNING('No quiz records found.'))
            return

        for quiz in quizzes:
            self.stdout.write(f'\n📝 Quiz ID: {quiz.id}')
            self.stdout.write(f'   User: {quiz.user.username if quiz.user else "Anonymous"}')
            self.stdout.write(f'   Score: {quiz.score}/{quiz.total_questions} ({quiz.percentage}%)')
            self.stdout.write(f'   Date: {quiz.timestamp.strftime("%Y-%m-%d %H:%M:%S")}')
            self.stdout.write(f'   Wrong Questions: {len(quiz.wrong_questions)}')
            if quiz.wrong_questions:
                self.stdout.write(f'   Wrong: {", ".join(quiz.wrong_questions[:3])}...')
            self.stdout.write(f'   Answers: {len(quiz.full_answers)} questions answered')

    def view_scan_data(self, limit, username=None):
        self.stdout.write('\n🔍 SCAN LOGS:')
        self.stdout.write('-' * 30)
        
        queryset = ScanLog.objects.all().order_by('-scan_time')
        if username:
            queryset = queryset.filter(user__username=username)
        
        scans = queryset[:limit]
        
        if not scans:
            self.stdout.write(self.style.WARNING('No scan records found.'))
            return

        for scan in scans:
            status_color = self.style.SUCCESS if scan.result == 'CLEAN' else self.style.ERROR
            self.stdout.write(f'\n🔍 Scan ID: {scan.id}')
            self.stdout.write(f'   Type: {scan.scan_type}')
            self.stdout.write(f'   Target: {scan.target[:50]}...')
            self.stdout.write(f'   Result: {status_color(scan.result)}')
            self.stdout.write(f'   User: {scan.user.username if scan.user else "Anonymous"}')
            self.stdout.write(f'   Date: {scan.scan_time.strftime("%Y-%m-%d %H:%M:%S")}')

    def view_threat_data(self, limit):
        self.stdout.write('\n⚠️  THREAT LOGS:')
        self.stdout.write('-' * 30)
        
        queryset = ThreatLog.objects.all().order_by('-timestamp')
        threats = queryset[:limit]
        
        if not threats:
            self.stdout.write(self.style.WARNING('No threat records found.'))
            return

        for threat in threats:
            severity_color = {
                'low': self.style.SUCCESS,
                'medium': self.style.WARNING,
                'high': self.style.ERROR,
                'critical': lambda x: self.style.ERROR(f'🚨 {x}')
            }.get(threat.severity, self.style.WARNING)
            
            self.stdout.write(f'\n⚠️  Threat ID: {threat.id}')
            self.stdout.write(f'   Type: {threat.threat_type}')
            self.stdout.write(f'   Severity: {severity_color(threat.severity.upper())}')
            self.stdout.write(f'   Status: {threat.status}')
            self.stdout.write(f'   Description: {threat.description[:60]}...')
            self.stdout.write(f'   User: {threat.reported_by.username if threat.reported_by else "System"}')
            self.stdout.write(f'   Date: {threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")}')

    def view_login_data(self, limit, username=None):
        self.stdout.write('\n🔐 LOGIN LOGS:')
        self.stdout.write('-' * 30)
        
        queryset = LoginLog.objects.all().order_by('-login_time')
        if username:
            queryset = queryset.filter(user__username=username)
        
        logins = queryset[:limit]
        
        if not logins:
            self.stdout.write(self.style.WARNING('No login records found.'))
            return

        for login in logins:
            status_color = self.style.SUCCESS if login.status == 'success' else self.style.ERROR
            self.stdout.write(f'\n🔐 Login ID: {login.id}')
            self.stdout.write(f'   User: {login.user.username}')
            self.stdout.write(f'   Status: {status_color(login.status.upper())}')
            self.stdout.write(f'   IP: {login.ip_address}')
            self.stdout.write(f'   Session: {login.session_id[:8]}...')
            self.stdout.write(f'   Date: {login.login_time.strftime("%Y-%m-%d %H:%M:%S")}')

    def view_logout_data(self, limit, username=None):
        self.stdout.write('\n🚪 LOGOUT LOGS:')
        self.stdout.write('-' * 30)
        
        queryset = LogoutLog.objects.all().order_by('-logout_time')
        if username:
            queryset = queryset.filter(user__username=username)
        
        logouts = queryset[:limit]
        
        if not logouts:
            self.stdout.write(self.style.WARNING('No logout records found.'))
            return

        for logout in logouts:
            status_color = self.style.SUCCESS if logout.status == 'success' else self.style.ERROR
            self.stdout.write(f'\n🚪 Logout ID: {logout.id}')
            self.stdout.write(f'   User: {logout.user.username}')
            self.stdout.write(f'   Status: {status_color(logout.status.upper())}')
            self.stdout.write(f'   IP: {logout.ip_address}')
            self.stdout.write(f'   Session: {logout.session_id[:8]}...')
            self.stdout.write(f'   Date: {logout.logout_time.strftime("%Y-%m-%d %H:%M:%S")}')

    def view_users_data(self):
        self.stdout.write('\n👥 USER STATISTICS:')
        self.stdout.write('-' * 30)
        
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        staff_users = User.objects.filter(is_staff=True).count()
        superusers = User.objects.filter(is_superuser=True).count()
        
        self.stdout.write(f'📊 Total Users: {total_users}')
        self.stdout.write(f'✅ Active Users: {active_users}')
        self.stdout.write(f'👔 Staff Users: {staff_users}')
        self.stdout.write(f'👑 Superusers: {superusers}')
        
        # Recent users
        recent_users = User.objects.order_by('-date_joined')[:5]
        if recent_users:
            self.stdout.write('\n🆕 Recent Users:')
            for user in recent_users:
                self.stdout.write(f'   • {user.username} ({user.email}) - {user.date_joined.strftime("%Y-%m-%d")}')