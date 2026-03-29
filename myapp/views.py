from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.decorators import user_passes_test

def staff_required(user):
    return user.is_staff

def superuser_required(user):
    return user.is_superuser
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

def save_quiz_csv(quiz_log, questions, answers, score, wrong_answers):
    """
    Save quiz results to a CSV file on the server
    """
    # Create uploads directory if it doesn't exist
    uploads_dir = os.path.join(settings.BASE_DIR, 'uploads', 'quiz_results')
    os.makedirs(uploads_dir, exist_ok=True)
    
    # Generate filename with timestamp and username
    timestamp = quiz_log.timestamp.strftime('%Y%m%d_%H%M%S')
    username = quiz_log.user.username if quiz_log.user else 'anonymous'
    filename = f"quiz_result_{username}_{timestamp}.csv"
    filepath = os.path.join(uploads_dir, filename)
    
    # Write CSV file
    with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Header
        writer.writerow(['CyberPhishGuard Quiz Results'])
        writer.writerow([''])
        writer.writerow(['User:', quiz_log.user.username if quiz_log.user else 'Anonymous'])
        writer.writerow(['Date:', quiz_log.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Score:', f"{quiz_log.score}/{quiz_log.total_questions}"])
        writer.writerow(['Percentage:', f"{quiz_log.percentage}%"])
        writer.writerow([''])
        
        # Questions and answers
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
        
        # Summary
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

@login_required
def user_breakdown(request):
    user_stats = User.objects.aggregate(
        total=Count('id'),
        staff=Count('id', filter=Q(is_staff=True)),
        superusers=Count('id', filter=Q(is_superuser=True)),
        active=Count('id', filter=Q(is_active=True))
    )

    recent_users = User.objects.all().order_by('-date_joined')[:20]

    all_users = User.objects.annotate(latest_logout=Max('logoutlog__logout_time')).order_by('-date_joined')
    paginator = Paginator(all_users, 10)
    page_number = request.GET.get('page')
    users_page = paginator.get_page(page_number)

    context = {
        'user_stats': user_stats,
        'recent_users': recent_users,
        'users_page': users_page,
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    return render(request, 'myapp/user_breakdown.html', context)

@login_required
def logout_logs(request):
    logout_stats = LogoutLog.objects.aggregate(
        total=Count('id'),
        successful=Count('id', filter=Q(status='success')),
        failed=Count('id', filter=Q(status='failed'))
    )

    recent_logouts = LogoutLog.objects.select_related('user').order_by('-logout_time')[:20]

    all_logouts = LogoutLog.objects.select_related('user').order_by('-logout_time')
    paginator = Paginator(all_logouts, 10)
    page_number = request.GET.get('page')
    logouts_page = paginator.get_page(page_number)

    context = {
        'logout_stats': logout_stats,
        'recent_logouts': recent_logouts,
        'logouts_page': logouts_page,
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    return render(request, 'myapp/logout_logs.html', context)

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
    threats = ThreatLog.objects.all().order_by('-timestamp')
    paginator = Paginator(threats, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'myapp/all_threats.html', {'threats': page_obj, 'page_obj': page_obj})

@login_required
def scan_breakdown(request):
    scan_counts = ScanLog.objects.aggregate(
        total=Count('id'),
        url_scans=Count('id', filter=Q(scan_type='URL')),
        email_scans=Count('id', filter=Q(scan_type='EMAIL')),
        malware_scans=Count('id', filter=Q(scan_type='MALWARE'))
    )

    recent_url = ScanLog.objects.filter(scan_type='URL').order_by('-scan_time')[:10]
    recent_email = ScanLog.objects.filter(scan_type='EMAIL').order_by('-scan_time')[:10]
    recent_malware = ScanLog.objects.filter(scan_type='MALWARE').order_by('-scan_time')[:10]

    scan_activity = ScanLog.objects.filter(
        scan_time__gte=datetime.now() - timedelta(days=7)
    ).values('scan_type').annotate(count=Count('id')).order_by('-count')

    context = {
        'scan_counts': scan_counts,
        'recent_url': recent_url,
        'recent_email': recent_email,
        'recent_malware': recent_malware,
        'scan_activity': scan_activity,
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    return render(request, 'myapp/scan_breakdown.html', context)

@login_required
def threat_breakdown(request):
    threat_counts = ScanLog.objects.filter(result='THREAT').aggregate(
        total=Count('id'),
        url_threats=Count('id', filter=Q(scan_type='URL')),
        email_threats=Count('id', filter=Q(scan_type='EMAIL')),
        malware_threats=Count('id', filter=Q(scan_type='MALWARE'))
    )

    recent_url_threats = ScanLog.objects.filter(scan_type='URL', result='THREAT').order_by('-scan_time')[:10]
    recent_email_threats = ScanLog.objects.filter(scan_type='EMAIL', result='THREAT').order_by('-scan_time')[:10]
    recent_malware_threats = ScanLog.objects.filter(scan_type='MALWARE', result='THREAT').order_by('-scan_time')[:10]

    threat_activity = ScanLog.objects.filter(
        scan_time__gte=datetime.now() - timedelta(days=7),
        result='THREAT'
    ).values('scan_type').annotate(count=Count('id')).order_by('-count')

    context = {
        'threat_counts': threat_counts,
        'recent_url': recent_url_threats,
        'recent_email': recent_email_threats,
        'recent_malware': recent_malware_threats,
        'scan_activity': threat_activity,
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    return render(request, 'myapp/threat_breakdown.html', context)

@login_required
def threat_dashboard(request):
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('dashboard')
    return render(request, 'myapp/threat_dashboard.html')

@login_required
def malware_detection(request):
    if request.method == 'POST':
        if 'file' in request.FILES:
            file_obj = request.FILES['file']
            filename = file_obj.name
            file_content = file_obj.read()
            
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            
            is_malware, malware_name = is_malware_hash(sha256_hash)
            
            ScanLog.objects.create(
                scan_type='MALWARE',
                target=f"{filename} ({sha256_hash[:16]}...)",
                result='THREAT' if is_malware else 'CLEAN',
                user=request.user if request.user.is_authenticated else None
            )
            
            if is_malware:
                result = f"Malware Detected! ({malware_name})"
            else:
                result = "No known malware threats detected."
            
            return render(request, 'myapp/malware.html', {
                'result': result,
                'hash': sha256_hash
            })
    return render(request, 'myapp/malware.html')

def malware_visualization(request):
    return render(request, 'myapp/malware_visualization.html')

def quiz_csv_export(request):
    """Export latest quiz results as CSV after submit"""
    from django.http import HttpResponse
    import csv
    from io import StringIO

    questions = {
        "q1": {
            "question": "What is phishing?",
            "options": {"a": "A type of firewall", "b": "A fake attempt to steal personal data", "c": "An antivirus tool"},
            "answer": "b"
        },
        "q2": {
            "question": "Which password is the strongest?",
            "options": {"a": "123456", "b": "password", "c": "P@ssW0rd#9"},
            "answer": "c"
        },
        "q3": {
            "question": "What should you do with suspicious email links?",
            "options": {"a": "Click immediately", "b": "Ignore or report", "c": "Reply to sender"},
            "answer": "b"
        },
        "q4": {
            "question": "What does HTTPS stand for?",
            "options": {"a": "Hyper Text Transfer Protocol Secure", "b": "High Tech Secure Protocol", "c": "Home Tool Transfer Protocol System"},
            "answer": "a"
        },
        "q5": {
            "question": "What is two-factor authentication (2FA)?",
            "options": {"a": "Using two different passwords", "b": "A security method requiring two forms of verification", "c": "Logging in from two devices"},
            "answer": "b"
        },
        "q6": {
            "question": "Which of these is a sign of a phishing email?",
            "options": {"a": "Email from a known contact", "b": "Urgent requests for personal information", "c": "Company email with proper domain"},
            "answer": "b"
        },
        "q7": {
            "question": "What should you do before downloading software?",
            "options": {"a": "Download from any website", "b": "Verify the source and scan for viruses", "c": "Share your email first"},
            "answer": "b"
        },
        "q8": {
            "question": "What is malware?",
            "options": {"a": "A type of email", "b": "Malicious software designed to harm your system", "c": "A secure connection"},
            "answer": "b"
        },
        "q9": {
            "question": "How often should you update your passwords?",
            "options": {"a": "Never", "b": "Every few months or immediately if compromised", "c": "Once a year"},
            "answer": "b"
        },
        "q10": {
            "question": "What is a VPN used for?",
            "options": {"a": "To speed up your internet", "b": "To create a secure, encrypted connection", "c": "To store your passwords"},
            "answer": "b"
        }
    }

    response = HttpResponse(content_type='application/vnd.ms-excel')
    response['Content-Disposition'] = 'attachment; filename="quiz_answers_{}.csv"'.format(datetime.now().strftime("%Y%m%d_%H%M%S"))

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(['Q Num', 'Question', 'Your Answer', 'Correct Answer', 'Correct?', 'Score', 'Resources'])
    writer.writerow(['CURRENT SESSION', '', '', '', '', datetime.now().strftime('%d-%b'), 'Security Awareness Quiz'])
    writer.writerow([])

    if request.user.is_authenticated:
        latest_quiz = QuizLog.objects.filter(user=request.user).latest('timestamp')
        full_answers = getattr(latest_quiz, 'full_answers', {})
        score = latest_quiz.score
        wrong_count = len(latest_quiz.wrong_questions)
    else:
        full_answers = {}
        score = 0
        wrong_count = 0

    for key, q in questions.items():
        q_num = key[1:].upper()
        user_ans = full_answers.get(key, 'Not answered')
        correct_ans = q['options'][q['answer']]
        status = '✅ CORRECT' if user_ans == q['answer'] else '❌ WRONG'
        writer.writerow([q_num, q['question'][:25] + '...', user_ans, correct_ans, status, '', ''])

    writer.writerow([])
    writer.writerow(['SUMMARY', '', f'FINAL SCORE: {score}/10', '', wrong_count, '', 'Security Awareness Quiz Resources: Phishing, Passwords, HTTPS, 2FA, Malware, VPN'])

    response.write(output.getvalue())
    return response

@login_required
def quiz_awareness(request):
    questions = {
        "q1": {
            "question": "What is phishing?",
            "options": {"a": "A type of firewall", "b": "A fake attempt to steal personal data", "c": "An antivirus tool"},
            "answer": "b"
        },
        "q2": {
            "question": "Which password is the strongest?",
            "options": {"a": "123456", "b": "password", "c": "P@ssW0rd#9"},
            "answer": "c"
        },
        "q3": {
            "question": "What should you do with suspicious email links?",
            "options": {"a": "Click immediately", "b": "Ignore or report", "c": "Reply to sender"},
            "answer": "b"
        },
        "q4": {
            "question": "What does HTTPS stand for?",
            "options": {"a": "Hyper Text Transfer Protocol Secure", "b": "High Tech Secure Protocol", "c": "Home Tool Transfer Protocol System"},
            "answer": "a"
        },
        "q5": {
            "question": "What is two-factor authentication (2FA)?",
            "options": {"a": "Using two different passwords", "b": "A security method requiring two forms of verification", "c": "Logging in from two devices"},
            "answer": "b"
        },
        "q6": {
            "question": "Which of these is a sign of a phishing email?",
            "options": {"a": "Email from a known contact", "b": "Urgent requests for personal information", "c": "Company email with proper domain"},
            "answer": "b"
        },
        "q7": {
            "question": "What should you do before downloading software?",
            "options": {"a": "Download from any website", "b": "Verify the source and scan for viruses", "c": "Share your email first"},
            "answer": "b"
        },
        "q8": {
            "question": "What is malware?",
            "options": {"a": "A type of email", "b": "Malicious software designed to harm your system", "c": "A secure connection"},
            "answer": "b"
        },
        "q9": {
            "question": "How often should you update your passwords?",
            "options": {"a": "Never", "b": "Every few months or immediately if compromised", "c": "Once a year"},
            "answer": "b"
        },
        "q10": {
            "question": "What is a VPN used for?",
            "options": {"a": "To speed up your internet", "b": "To create a secure, encrypted connection", "c": "To store your passwords"},
            "answer": "b"
        }
    }

    if request.method == 'POST':
        answers = {}
        for key in questions.keys():
            if key in request.POST:
                answers[key] = request.POST[key]

        score = 0
        wrong_answers = []
        for key, q in questions.items():
            user_answer = answers.get(key)
            if user_answer == q['answer']:
                score += 1
            else:
                wrong_answer_text = user_answer if user_answer else 'Not answered'
                correct_text = q['options'][q['answer']]
                wrong_answers.append({
                    'question': q['question'],
                    'user_answer': wrong_answer_text,
                    'correct_answer': correct_text
                })

        context = {
            'submitted': True,
            'score': score,
            'questions': questions,
            'wrong_answers': wrong_answers
        }

        # Log quiz result if user authenticated
        if request.user.is_authenticated:
            percentage = (score / len(questions)) * 100
            full_answers = dict(answers)
            wrong_questions = [q['question'] for key, q in questions.items() if answers.get(key) != q['answer']]
            
            # Create quiz log entry
            quiz_log = QuizLog.objects.create(
                user=request.user,
                score=score,
                total_questions=len(questions),
                percentage=round(percentage, 2),
                full_answers=full_answers,
                wrong_questions=wrong_questions,
                timestamp=datetime.now()
            )
            
            # Save CSV file
            save_quiz_csv(quiz_log, questions, answers, score, wrong_answers)

        return render(request, 'myapp/quiz.html', context)
    else:
        context = {'questions': questions}
        return render(request, 'myapp/quiz.html', context)

@login_required
def resources(request):
    return render(request, 'myapp/resources.html')

@login_required
def quiz_history(request):
    """Display user's quiz history"""
    quiz_logs = QuizLog.objects.filter(user=request.user).order_by('-timestamp')
    
    paginator = Paginator(quiz_logs, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'quiz_logs': page_obj,
        'page_obj': page_obj,
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    return render(request, 'myapp/quiz_history.html', context)

@login_required
def scan_url(request):
    detector = ThreatDetector()
    if request.method == 'POST':
        form = URLScanForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            result = detector.detect_phishing_url(url)
            
            ScanLog.objects.create(
                scan_type='URL',
                target=url,
                result='THREAT' if result['is_phishing'] else 'CLEAN',
                user=request.user
            )
            
            context = {
                'form': URLScanForm(),
                'scan_result': result
            }
            return render(request, 'myapp/scan_url.html', context)
    else:
        form = URLScanForm()
    
    context = {'form': form}
    return render(request, 'myapp/scan_url.html', context)

@login_required
def scan_email(request):
    detector = ThreatDetector()
    if request.method == 'POST':
        form = EmailScanForm(request.POST)
        if form.is_valid():
            subject = form.cleaned_data['email_subject']
            body = form.cleaned_data['email_body']
            result = detector.detect_spam_email(subject, body)
            ScanLog.objects.create(
                scan_type='EMAIL',
                target=f"{subject[:50]}...",
                result='THREAT' if result['is_spam'] else 'CLEAN',
                user=request.user
            )
            context = {
                'form': EmailScanForm(),
                'scan_result': result
            }
            return render(request, 'myapp/scan_email.html', context)
    form = EmailScanForm()
    context = {'form': form}
    return render(request, 'myapp/scan_email.html', context)

def logout_view(request):
    if request.user.is_authenticated:
        LogoutLog.objects.create(
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            session_id=request.session.session_key,
            status='success'
        )
    logout(request)
    request.session.flush()
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')

@user_passes_test(superuser_required, login_url='/login/')
@login_required
def superuser_dashboard(request):
    # Superuser only stats
    superuser_stats = {
        'all_users': User.objects.count(),
        'staff_users': User.objects.filter(is_staff=True).count(),
        'regular_users': User.objects.filter(is_staff=False).count(),
        'total_threats': ThreatLog.objects.count(),
        'open_threats': ThreatLog.objects.filter(status__in=['detected', 'analyzing']).count(),
        'all_scans': ScanLog.objects.count(),
        'threat_scans': ScanLog.objects.filter(result='THREAT').count(),
        'recent_logins': LoginLog.objects.order_by('-login_time')[:10],
        'failed_logins': LoginLog.objects.filter(status='failed').count(),
    }
    return render(request, 'myapp/superuser_dashboard.html', {'stats': superuser_stats})
