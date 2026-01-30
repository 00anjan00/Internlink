from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import re

from .utils import normalize_np_phone
from .models import Profile

ROLE_CHOICES = [("STUDENT", "Student"), ("COMPANY", "Company")]

# -----------------------
# Shared validators
# -----------------------

_LETTERS_RE = re.compile(r"^[A-Za-z][A-Za-z\s.&'-]{0,}$")

def _clean_letters_only(raw: str, field_label: str) -> str:
    v = (raw or "").strip()

    if not v:
        raise forms.ValidationError(f"{field_label} is required.")

    if not _LETTERS_RE.match(v):
        raise forms.ValidationError(
            f"{field_label} must contain letters only (spaces, ., &, ', - allowed). No numbers."
        )

    # optional: prevent super-short junk like just "." or "-"
    if len(re.sub(r"[\s.&'-]", "", v)) < 2:
        raise forms.ValidationError(f"{field_label} is too short.")

    return v


# -----------------------
# Shared phone cleaning
# -----------------------
def _clean_unique_phone(raw_phone: str) -> str:
    """
    Normalize phone and ensure it is unique in Profile table.
    """
    try:
        phone = normalize_np_phone(raw_phone)
    except ValueError as e:
        raise forms.ValidationError(str(e))

    if Profile.objects.filter(phone=phone).exists():
        raise forms.ValidationError("This phone number is already registered.")
    return phone


class RoleSelectForm(forms.Form):
    role = forms.ChoiceField(choices=ROLE_CHOICES, widget=forms.RadioSelect)


class StudentStepForm(forms.Form):
    full_name = forms.CharField(
        max_length=120,
        label="Full Name",
        widget=forms.TextInput(attrs={"placeholder": "Your full name"})
    )
    phone = forms.CharField(
        max_length=30,
        label="Phone Number",
        widget=forms.TextInput(attrs={"placeholder": "98XXXXXXXX or +97798XXXXXXXX"})
    )
    country = forms.CharField(
        max_length=60,
        label="Country",
        widget=forms.TextInput(attrs={"placeholder": "Nepal"})
    )
    city = forms.CharField(
        max_length=60,
        required=False,
        label="City (optional)",
        widget=forms.TextInput(attrs={"placeholder": "Pokhara"})
    )

    university = forms.CharField(
        max_length=140,
        label="University / College",
        widget=forms.TextInput(attrs={"placeholder": "TU, Tribhuvan University, King's College..."})
    )
    degree = forms.CharField(
        max_length=140,
        label="Degree / Program",
        widget=forms.TextInput(attrs={"placeholder": "BSc CSIT / BIT / BCA ..."})
    )
    graduation_year = forms.IntegerField(
        min_value=2000,
        max_value=2100,
        label="Graduation Year",
        widget=forms.NumberInput(attrs={"placeholder": "2026"})
    )

    skills = forms.CharField(
        max_length=400,
        required=False,
        label="Skills (optional)",
        widget=forms.TextInput(attrs={"placeholder": "Django, HTML, CSS, MySQL..."})
    )
    linkedin_url = forms.URLField(
        required=False,
        label="LinkedIn URL (optional)",
        widget=forms.URLInput(attrs={"placeholder": "https://linkedin.com/in/yourname"})
    )

    def clean_full_name(self):
        return _clean_letters_only(self.cleaned_data.get("full_name"), "Full Name")

    def clean_country(self):
        return _clean_letters_only(self.cleaned_data.get("country"), "Country")

    def clean_city(self):
        v = (self.cleaned_data.get("city") or "").strip()
        if not v:
            return v
        return _clean_letters_only(v, "City")

    def clean_university(self):
        return _clean_letters_only(self.cleaned_data.get("university"), "University / College")

    def clean_phone(self):
        return _clean_unique_phone(self.cleaned_data["phone"])


class CompanyStepForm(forms.Form):
    full_name = forms.CharField(
        max_length=120,
        label="Contact Person Name",
        widget=forms.TextInput(attrs={"placeholder": "Your name"})
    )
    phone = forms.CharField(
        max_length=30,
        label="Company Phone Number",
        widget=forms.TextInput(attrs={"placeholder": "98XXXXXXXX or +97798XXXXXXXX"})
    )
    country = forms.CharField(
        max_length=60,
        label="Country",
        widget=forms.TextInput(attrs={"placeholder": "Nepal"})
    )
    city = forms.CharField(
        max_length=60,
        required=False,
        label="City (optional)",
        widget=forms.TextInput(attrs={"placeholder": "Pokhara"})
    )

    company_name = forms.CharField(
        max_length=160,
        label="Company Name",
        widget=forms.TextInput(attrs={"placeholder": "Company Pvt. Ltd."})
    )
    industry = forms.CharField(
        max_length=120,
        label="Industry",
        widget=forms.TextInput(attrs={"placeholder": "Software / Marketing / Finance..."})
    )
    website = forms.URLField(
        required=False,
        label="Website (optional)",
        widget=forms.URLInput(attrs={"placeholder": "https://company.com"})
    )
    address = forms.CharField(
        max_length=200,
        required=False,
        label="Address (optional)",
        widget=forms.TextInput(attrs={"placeholder": "Street, Area"})
    )
    hr_name = forms.CharField(
        max_length=120,
        required=False,
        label="HR / Recruiter Name (optional)",
        widget=forms.TextInput(attrs={"placeholder": "HR contact name"})
    )

    def clean_full_name(self):
        return _clean_letters_only(self.cleaned_data.get("full_name"), "Contact Person Name")

    def clean_country(self):
        return _clean_letters_only(self.cleaned_data.get("country"), "Country")

    def clean_city(self):
        v = (self.cleaned_data.get("city") or "").strip()
        if not v:
            return v
        return _clean_letters_only(v, "City")

    def clean_industry(self):
        return _clean_letters_only(self.cleaned_data.get("industry"), "Industry")

    def clean_hr_name(self):
        v = (self.cleaned_data.get("hr_name") or "").strip()
        if not v:
            return v
        return _clean_letters_only(v, "HR / Recruiter Name")

    def clean_company_name(self):
        # allow numbers here (Cloud9, Tech360, etc.)
        return (self.cleaned_data.get("company_name") or "").strip()

    def clean_phone(self):
        return _clean_unique_phone(self.cleaned_data["phone"])


class AccountStepForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        label="Username",
        widget=forms.TextInput(attrs={"placeholder": "Choose a username"})
    )
    email = forms.EmailField(
        label="Email Address",
        widget=forms.EmailInput(attrs={"placeholder": "you@example.com"})
    )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"placeholder": "Create a strong password"})
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={"placeholder": "Re-enter password"})
    )
    agree = forms.BooleanField(
        required=True,
        label="I agree to the terms and policies"
    )

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already registered.")
        return email

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1")
        p2 = cleaned.get("password2")

        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Passwords do not match.")

        if p1:
            try:
                validate_password(p1)
            except ValidationError as e:
                self.add_error("password1", e.messages)

        return cleaned


class LoginForm(forms.Form):
    identifier = forms.CharField(
        max_length=150,
        label="Email / Username / Phone",
        widget=forms.TextInput(attrs={"placeholder": "Email, username, or phone"})
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"placeholder": "Enter your password"})
    )
    remember_me = forms.BooleanField(required=False, label="Remember me")

class EmailOTPForm(forms.Form):
    code = forms.CharField(
        max_length=6,
        min_length=6,
        label="Verification code",
        widget=forms.TextInput(attrs={
            "placeholder": "6-digit code",
            "inputmode": "numeric",
            "autocomplete": "one-time-code",
            "pattern": r"\d{6}",
        })
    )

    def clean_code(self):
        code = (self.cleaned_data["code"] or "").strip()
        if not code.isdigit():
            raise forms.ValidationError("Code must be 6 digits.")
        return code