from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Profile(models.Model):
    ROLE_CHOICES = [
        ("STUDENT", "Student"),
        ("COMPANY", "Company"),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

    full_name = models.CharField(max_length=120)
    phone = models.CharField(max_length=30, unique=True)

    country = models.CharField(max_length=60)
    city = models.CharField(max_length=60, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} ({self.role})"


class StudentProfile(models.Model):
    profile = models.OneToOneField(Profile, on_delete=models.CASCADE, related_name="student")

    university = models.CharField(max_length=140)
    degree = models.CharField(max_length=140)
    graduation_year = models.PositiveIntegerField()

    skills = models.CharField(max_length=400, blank=True)     # "Python, Django, SQL"
    linkedin_url = models.URLField(blank=True)
    portfolio_url = models.URLField(blank=True)

    def __str__(self):
        return f"Student: {self.profile.user.username}"


class CompanyProfile(models.Model):
    profile = models.OneToOneField(Profile, on_delete=models.CASCADE, related_name="company")

    company_name = models.CharField(max_length=160)
    industry = models.CharField(max_length=120)
    website = models.URLField(blank=True)

    address = models.CharField(max_length=200, blank=True)
    company_size = models.CharField(max_length=50, blank=True)   # "1-10", "11-50" etc.
    hr_name = models.CharField(max_length=120, blank=True)

    def __str__(self):
        return f"Company: {self.company_name}"

class EmailOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="email_otp")
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveIntegerField(default=0)
    is_used = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() >= self.expires_at