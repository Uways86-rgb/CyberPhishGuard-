from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q, Count
from django.core.paginator import Paginator
from django.db.models import Max
from django.db.models.functions import TruncDate
from datetime import datetime, timedelta
from .forms import CustomUserCreationForm, URLScanForm, EmailScanForm
from .threat_detector import ThreatDetector
from .malware_hashes import is_malware_hash
from .models import ThreatLog, ScanLog, ThreatIntelligence, QuizLog, LoginLog, LogoutLog
import json
import os
import hashlib
import csv
from django.http import HttpResponse
from django.conf import settings
from datetime import datetime

def staff_required(user):
    return user.is_staff

def superuser_required(user):
    return user.is_superuser

def save_quiz_csv(quiz_log, questions, answers, score, wrong_answers):
    """
    Save quiz results to a CSV file on the server
    """
    uploads_dir = os.path.join(settings.BASE_DIR, 'uploads', 'quiz_results')
    os.makedirs(uploads_dir, exist_ok=True)
    
    timestamp = quiz_log.timestamp.strftime('%Y%m%d_%H%M%S')
    username = quiz_log.user.username if quiz_log.user else 'anonymous'
    filename = f"quiz_result_{username}_{timestamp}.csv"
    filepath = os.path.join(uploads_dir, filename)
    
    with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(['CyberPhishGuard Quiz Results'])
        writer.writerow([''])
        writer.writerow(['User:', quiz_log.user.username if quiz_log.user else 'Anonymous'])
        writer.writerow(['Date:', quiz_log.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Score:', f"{quiz_log.score}/{quiz_log.total_questions}"])
        writer.writerow(['Percentage:', f"{quiz_log.percentage}%"])
        writer.writerow([''])
        
        writer.writerow(['Question Number', 'Question', 'Your Answer', 'Correct Answer', 'Status'])
        writer.writerow([''])
        
        for key, q in questions.items():
            q_num = key[1:].upper()
            user_ans = answers.get(key, 'Not answered')
            correct_ans = q['options'][q['answer']]
            status = 'CORRECT' if user_ans == q['answer'] else 'WRONG'
            
            writer.writerow([
                q_num,
                q['question'],
                user_ans,
                correct_ans,
                status
            ])
        
        writer.writerow([''])
        writer.writerow(['Wrong Answers Details:'])
        writer.writerow([''])
        
        for item in wrong_answers:
            writer.writerow(['Question:', item['question']])
            writer.writerow(['Your Answer:', item['user_answer']])
            writer.writerow(['Correct Answer:', item['correct_answer']])
            writer.writerow([''])
        
        writer.writerow(['Summary:'])
        writer.writerow(['Total Questions:', quiz_log.total_questions])
        writer.writerow(['Correct Answers:', quiz_log.score])
        writer.writerow(['Wrong Answers:', len(wrong_answers)])
        writer.writerow(['Percentage:', f"{quiz_log.percentage}%"])
        writer.writerow(['Achievement:', 'Perfect Score!' if quiz_log.score == quiz_log.total_questions else 'Good Job!' if quiz_log.score >= 7 else 'Keep Learning!'])
    
    return filepath

def home(request):
    scan_activity = ScanLog.objects.filter(
        scan_time__gte=datetime.now() - timedelta(days=7)
    ).annotate(
        date=TruncDate('scan_time')
    ).values('date').annotate(
        total_scans=Count('id'),
        threats=Count('id', filter=Q(result='THREAT'))
    ).order_by('date')

    scan_dates = []
    scan_counts = []
    threat_counts = []

    for entry in scan_activity:
        if entry['date'] is not None:
            scan_dates.append(entry['date'].strftime('%Y-%m-%d'))
            scan_counts.append(entry['total_scans'])
            threat_counts.append(entry['threats'])

    context = {
        'total_scans': 15420,
        'threats_detected': 342,
        'active_users': 89,
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'scan_dates': scan_dates,
        'scan_counts': scan_counts,
        'threat_counts': threat_counts
    }
    return render(request, 'myapp/index.html', context)

def about(request):
    return render(request, 'myapp/about.html')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                LoginLog.objects.create(
                    user=user,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    session_id=request.session.session_key or '',
                    status='success'
                )
                messages.success(request, f'Welcome back, {username}!')
                return redirect('dashboard')
            else:
                try:
                    user_obj = User.objects.get(username=username)
                    LoginLog.objects.create(
                        user=user_obj,
                        ip_address=request.META.get('REMOTE_ADDR'),
                        session_id=request.session.session_key or '',
                        status='failed'
                    )
                except User.DoesNotExist:
                    pass
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Please provide both username and password.')

    return render(request, 'myapp/login.html')

@login_required
def dashboard(request):
    threats = ThreatLog.objects.all()

    threat_stats = {
        'total': threats.count(),
        'critical': threats.filter(severity='critical').count(),
        'high': threats.filter(severity='high').count(),
        'medium': threats.filter(severity='medium').count(),
        'low': threats.filter(severity='low').count(),
        'resolved': threats.filter(status='resolved').count(),
        'unresolved': threats.exclude(status='resolved').count(),
        'detected': threats.filter(status='detected').count(),
        'analyzing': threats.filter(status='analyzing').count(),
        'contained': threats.filter(status='contained').count(),
        'phishing': threats.filter(threat_type='phishing').count(),
        'malware': threats.filter(threat_type='malware').count(),
    }

    recent_threats = threats.order_by('-timestamp')[:5]

    scan_counts = ScanLog.objects.aggregate(
        url_scans=Count('id', filter=Q(scan_type='URL')),
        email_scans=Count('id', filter=Q(scan_type='EMAIL')),
        malware_scans=Count('id', filter=Q(scan_type='MALWARE'))
    )

    context = {
        'total_scans': ScanLog.objects.count(),
        'url_scans': scan_counts['url_scans'],
        'email_scans': scan_counts['email_scans'],
        'malware_scans': scan_counts['malware_scans'],
        'threats_detected': threat_stats['total'],
        'uptime_hours': 247,
        'active_users': User.objects.count(),
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'recent_threats': recent_threats,
        'threat_stats': threat_stats
    }
    return render(request, 'myapp/dashboard.html', context)

# ... (rest of functions with fixed register_view)

# Fixed register_view
def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            if User.objects.filter(username=username).exists():
                form.add_error('username', 'A user with that username already exists.')
            else:
                user = form.save()
                messages.success(request, f'Account created successfully for {user.username}. Please log in.')
                return redirect('login')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomUserCreationForm()

    return render(request, 'myapp/register.html', {'form': form})

# Fixed admin_register_view
@login_required
def admin_register_view(request):
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('dashboard')

    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            if User.objects.filter(username=username).exists():
                form.add_error('username', 'A user with that username already exists.')
            else:
                user = form.save()
                messages.success(request, f'User {user.username} has been registered successfully.')
                return redirect('user_management')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomUserCreationForm()

    return render(request, 'myapp/admin_register.html', {'form': form})

# Rest of the views.py code remains the same...

