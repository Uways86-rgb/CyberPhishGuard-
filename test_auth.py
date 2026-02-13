import os
import sys
import django

# Add the project directory to sys.path
sys.path.append(os.path.join(os.getcwd(), 'mysite'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
django.setup()

from django.contrib.auth import authenticate
from django.contrib.auth.models import User

# Check if user exists
try:
    user = User.objects.get(username='testuser')
    print(f"User 'testuser' exists. Active: {user.is_active}")
except User.DoesNotExist:
    print("User 'testuser' does not exist.")

# Try to authenticate
user = authenticate(username='testuser', password='password123')
if user is not None:
    print("Authentication successful!")
else:
    print("Authentication failed.")
