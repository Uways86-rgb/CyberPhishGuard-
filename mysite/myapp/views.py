from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q
from datetime import datetime, timedelta
from .forms import CustomUserCreationForm, URLScanForm, EmailScanForm
from .threat_detector import ThreatDetector
from .models import ThreatLog, ScanLog, ThreatIntelligence
import os
import hashlib

def home(request):
    # Mock data for stats and scan activity chart
    from django.db.models import Count
    from django.db.models.functions import TruncDate

    # Get scan activity over the last 7 days
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
                messages.success(request, f'Welcome back, {username}!')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Please provide both username and password.')

    return render(request, 'myapp/login.html')

@login_required
def dashboard(request):
    threats = ThreatLog.objects.all()

    # Enhanced threat stats
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

    # Get 5 most recent threats
    recent_threats = threats.order_by('-timestamp')[:5]

    context = {
        'total_scans': ScanLog.objects.count(),
        'threats_detected': threat_stats['total'],
        'uptime_hours': 247,
        'active_users': User.objects.count(),
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'recent_threats': recent_threats,
        'threat_stats': threat_stats
    }
    return render(request, 'myapp/dashboard.html', context)

@login_required
def scan_url(request):
    """Scan URL for phishing and malware"""
    detector = ThreatDetector()
    scan_result = None

    if request.method == 'POST':
        form = URLScanForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']

            # Check if URL is already blacklisted
            blacklisted = ThreatIntelligence.objects.filter(
                indicator_type='URL',
                indicator_value=url,
                is_active=True
            ).exists()

            if blacklisted:
                scan_result = {
                    'blocked': True,
                    'is_phishing': True,
                    'confidence_score': 100,
                    'alerts': ['URL is blacklisted and blocked'],
                    'risk_level': 'high'
                }
                messages.error(request, 'URL is blacklisted and blocked!')
            else:
                scan_result = detector.detect_phishing_url(url)

                # Log the scan
                ScanLog.objects.create(
                    scan_type='URL',
                    target=url,
                    result='THREAT' if scan_result['is_phishing'] else 'CLEAN',
                    user=request.user
                )

                # Log the threat if detected and add to blacklist
                if scan_result['is_phishing']:
                    # Add to blacklist
                    ThreatIntelligence.objects.create(
                        indicator_type='URL',
                        indicator_value=url,
                        threat_type='phishing',
                        severity='high' if scan_result['confidence_score'] >= 70 else 'medium',
                        description=f"Phishing URL detected: {', '.join(scan_result['alerts'])}",
                        source='URL Scanner'
                    )

                    threat_data = {
                        'threat_type': 'phishing',
                        'severity': 'high' if scan_result['confidence_score'] >= 70 else 'medium',
                        'source_ip': request.META.get('REMOTE_ADDR'),
                        'url': url,
                        'description': f"Phishing URL detected: {', '.join(scan_result['alerts'])}",
                        'detection_method': 'URL Scanner',
                        'confidence_score': scan_result['confidence_score']
                    }
                    detector.log_threat(threat_data, request.user)
                    messages.warning(request, 'Phishing URL detected, logged, and added to blacklist!')
                else:
                    messages.success(request, 'URL appears to be safe.')

    else:
        form = URLScanForm()

    return render(request, 'myapp/scan_url.html', {
        'form': form,
        'scan_result': scan_result
    })

@login_required
def scan_email(request):
    """Scan email for spam"""
    detector = ThreatDetector()
    scan_result = None

    if request.method == 'POST':
        form = EmailScanForm(request.POST)
        if form.is_valid():
            subject = form.cleaned_data['email_subject']
            body = form.cleaned_data['email_body']

            scan_result = detector.detect_spam_email(subject, body)

            # Log the scan
            ScanLog.objects.create(
                scan_type='EMAIL',
                target=f"Subject: {subject}",
                result='THREAT' if scan_result['is_spam'] else 'CLEAN',
                user=request.user
            )

            # Log the threat if detected
            if scan_result['is_spam']:
                threat_data = {
                    'threat_type': 'spam',
                    'severity': 'high' if scan_result['confidence_score'] >= 70 else 'medium',
                    'source_ip': request.META.get('REMOTE_ADDR'),
                    'description': f"Spam email detected: {', '.join(scan_result['alerts'])}",
                    'detection_method': 'Email Scanner',
                    'confidence_score': scan_result['confidence_score']
                }
                detector.log_threat(threat_data, request.user)
                messages.warning(request, 'Spam email detected and logged!')
            else:
                messages.success(request, 'Email appears to be legitimate.')

    else:
        form = EmailScanForm()

    return render(request, 'myapp/scan_email.html', {
        'form': form,
        'scan_result': scan_result
    })

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, f'Account created successfully for {user.username}. Please log in.')
            return redirect('login')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomUserCreationForm()

    return render(request, 'myapp/register.html', {'form': form})

@login_required
def admin_register_view(request):
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('dashboard')

    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, f'User {user.username} has been registered successfully.')
            return redirect('user_management')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomUserCreationForm()

    return render(request, 'myapp/admin_register.html', {'form': form})

@login_required
def user_management(request):
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('dashboard')

    users = User.objects.all()
    return render(request, 'myapp/user_management.html', {'users': users})

@login_required
def all_threats(request):
    from django.core.paginator import Paginator

    threats = ThreatLog.objects.all().order_by('-timestamp')
    paginator = Paginator(threats, 10)  # Show 10 threats per page

    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'myapp/all_threats.html', {'threats': page_obj, 'page_obj': page_obj})

@login_required
def threat_dashboard(request):
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('dashboard')

    # Placeholder for threat dashboard
    return render(request, 'myapp/threat_dashboard.html')



def logout_view(request):
    logout(request)
    request.session.flush()  # Clear the session completely
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')
