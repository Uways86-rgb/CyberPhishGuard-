import os
import sys
import django

# Add the project directory to sys.path
sys.path.append(os.path.join(os.getcwd(), 'mysite'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
django.setup()

from django.contrib.auth.models import User

if not User.objects.filter(username='testuser').exists():
    User.objects.create_user('testuser', 'test@example.com', 'password123')
    print("Test user created.")
else:
    print("Test user already exists.")
