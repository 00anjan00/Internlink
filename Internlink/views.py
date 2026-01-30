from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.db import transaction, IntegrityError

from .utils import normalize_np_phone, looks_like_phone, create_or_refresh_email_otp
from .forms import (
    RoleSelectForm, StudentStepForm, CompanyStepForm,
    AccountStepForm, LoginForm, EmailOTPForm
)
from .models import Profile, StudentProfile, CompanyProfile
from .emails import send_verification_code_email


REG_SESSION_KEY = "internlink_reg"
VERIFY_SESSION_KEY = "internlink_verify_user_id"
MAX_OTP_ATTEMPTS = 5


# ===============================
# Landing / Homes
# ===============================
def landing(request):
    if request.user.is_authenticated:
        return redirect("home_redirect")
    return render(request, "landing.html")


@login_required
def home_redirect(request):
    if request.user.is_staff or request.user.is_superuser:
        return redirect("/admin/")

    prof = Profile.objects.filter(user=request.user).first()
    if not prof:
        return redirect("landing")

    return redirect("company_home" if prof.role == "COMPANY" else "student_home")


@login_required
def student_home(request):
    prof = Profile.objects.filter(user=request.user).first()
    return render(request, "student_home.html", {"profile": prof})


@login_required
def company_home(request):
    prof = Profile.objects.filter(user=request.user).first()
    return render(request, "company_home.html", {"profile": prof})


def logout_view(request):
    logout(request)
    return redirect("landing")


# ===============================
# Registration Wizard Helpers
# ===============================
def _reg_reset(request):
    request.session.pop(REG_SESSION_KEY, None)


def _reg_get(request):
    return request.session.get(REG_SESSION_KEY, {})


def _reg_set(request, data: dict):
    request.session[REG_SESSION_KEY] = data
    request.session.modified = True


# ===============================
# Registration Wizard Steps
# ===============================
def register_start(request):
    _reg_reset(request)
    return redirect("register_role")


def register_role(request):
    data = _reg_get(request)
    form = RoleSelectForm(request.POST or None, initial={"role": data.get("role")})

    if request.method == "POST" and form.is_valid():
        data["role"] = form.cleaned_data["role"]
        _reg_set(request, data)
        return redirect("register_details")

    return render(request, "register_role.html", {"form": form, "step": 1})


def register_details(request):
    data = _reg_get(request)
    role = data.get("role")

    if role not in ("STUDENT", "COMPANY"):
        return redirect("register_role")

    FormClass = StudentStepForm if role == "STUDENT" else CompanyStepForm
    form = FormClass(request.POST or None, initial=data.get("details", {}))

    if request.method == "POST" and form.is_valid():
        data["details"] = form.cleaned_data  # phone already normalized in form
        _reg_set(request, data)
        return redirect("register_account")

    return render(request, "register_details.html", {"form": form, "role": role, "step": 2})


def register_account(request):
    data = _reg_get(request)
    role = data.get("role")
    details = data.get("details")

    if role not in ("STUDENT", "COMPANY") or not details:
        return redirect("register_role")

    form = AccountStepForm(request.POST or None, initial=data.get("account", {}))

    if request.method == "POST" and form.is_valid():
        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    username=form.cleaned_data["username"],
                    email=form.cleaned_data["email"],
                    password=form.cleaned_data["password1"],
                )

                # Must verify email first
                user.is_active = False
                user.save(update_fields=["is_active"])

                profile = Profile.objects.create(
                    user=user,
                    role=role,
                    full_name=details["full_name"],
                    phone=details["phone"],
                    country=details["country"],
                    city=details.get("city", ""),
                )

                if role == "STUDENT":
                    StudentProfile.objects.create(
                        profile=profile,
                        university=details["university"],
                        degree=details["degree"],
                        graduation_year=details["graduation_year"],
                        skills=details.get("skills", ""),
                        linkedin_url=details.get("linkedin_url", ""),
                    )
                else:
                    CompanyProfile.objects.create(
                        profile=profile,
                        company_name=details["company_name"],
                        industry=details["industry"],
                        website=details.get("website", ""),
                        address=details.get("address", ""),
                        hr_name=details.get("hr_name", ""),
                    )

                # Create OTP + send email AFTER DB commit succeeds
                def _send_otp():
                    otp = create_or_refresh_email_otp(user, minutes_valid=10)
                    send_verification_code_email(user, otp.code)

                transaction.on_commit(_send_otp)

            # clear wizard session
            _reg_reset(request)

            # store verify user id for OTP page
            request.session[VERIFY_SESSION_KEY] = user.id
            request.session.modified = True

            messages.success(request, "Account created! We sent a 6-digit verification code to your email.")
            return redirect("verify_email_code")

        except IntegrityError:
            form.add_error("username", "This username is already taken.")
            form.add_error("email", "This email is already registered.")
            return render(request, "register_account.html", {"form": form, "step": 3})

        except Exception as e:
            form.add_error(None, f"Email could not be sent: {e}")
            return render(request, "register_account.html", {"form": form, "step": 3})

    return render(request, "register_account.html", {"form": form, "step": 3})


# ===============================
# OTP Verify + Resend
# ===============================
def verify_email_code(request):
    user_id = request.session.get(VERIFY_SESSION_KEY)
    if not user_id:
        messages.info(request, "No verification session found. Please log in or register again.")
        return redirect("login")

    user = User.objects.filter(id=user_id).first()
    if not user:
        request.session.pop(VERIFY_SESSION_KEY, None)
        messages.error(request, "Verification session expired. Please register again.")
        return redirect("register_start")

    otp = getattr(user, "email_otp", None)
    if not otp or otp.is_used:
        messages.error(request, "No active code found. Please resend a new code.")
        return redirect("resend_email_code")

    form = EmailOTPForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        code = form.cleaned_data["code"]

        if otp.is_expired():
            messages.error(request, "Code expired. Please request a new one.")
            return redirect("resend_email_code")

        if otp.attempts >= MAX_OTP_ATTEMPTS:
            messages.error(request, "Too many attempts. Please request a new code.")
            return redirect("resend_email_code")

        if code != otp.code:
            otp.attempts += 1
            otp.save(update_fields=["attempts"])
            messages.error(request, "Invalid code. Try again.")
            return render(request, "verify_email_code.html", {"form": form, "email": user.email})

        # success
        user.is_active = True
        user.save(update_fields=["is_active"])
        otp.is_used = True
        otp.save(update_fields=["is_used"])

        request.session.pop(VERIFY_SESSION_KEY, None)

        messages.success(request, "Email verified! You can now log in.")
        return redirect("login")

    return render(request, "verify_email_code.html", {"form": form, "email": user.email})


def resend_email_code(request):
    user_id = request.session.get(VERIFY_SESSION_KEY)
    user = User.objects.filter(id=user_id).first() if user_id else None

    # If we have a session user, resend directly
    if user and not user.is_active:
        otp = create_or_refresh_email_otp(user, minutes_valid=10)
        send_verification_code_email(user, otp.code)
        messages.success(request, "A new code has been sent to your email.")
        return redirect("verify_email_code")

    # Optional fallback: allow entering email to resend (don’t reveal existence)
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip().lower()
        user2 = User.objects.filter(email__iexact=email).first()
        if user2 and not user2.is_active:
            otp = create_or_refresh_email_otp(user2, minutes_valid=10)
            send_verification_code_email(user2, otp.code)

        messages.success(request, "If the email exists, we sent a new code.")
        return redirect("login")

    return render(request, "resend_email_code.html")


# ===============================
# Login (username / email / phone)
# ===============================
def login_page(request):
    if request.user.is_authenticated:
        return redirect("home_redirect")

    form = LoginForm(request.POST or None)
    error = None

    if request.method == "POST" and form.is_valid():
        identifier = form.cleaned_data["identifier"].strip()
        password = form.cleaned_data["password"]
        remember = form.cleaned_data.get("remember_me", False)

        user_obj = User.objects.filter(username=identifier).first()

        if not user_obj:
            user_obj = User.objects.filter(email__iexact=identifier).first()

        if not user_obj and looks_like_phone(identifier):
            try:
                phone = normalize_np_phone(identifier)
                prof = Profile.objects.filter(phone=phone).select_related("user").first()
                user_obj = prof.user if prof else None
            except ValueError:
                user_obj = None

        # If found but not verified
        if user_obj and not user_obj.is_active:
            # put them into verify flow
            request.session[VERIFY_SESSION_KEY] = user_obj.id
            request.session.modified = True
            error = "Please verify your email before logging in. We can resend you a code."
            return render(request, "login.html", {"form": form, "error": error})

        user = authenticate(
            request,
            username=user_obj.username,
            password=password
        ) if user_obj else None

        if user:
            login(request, user)
            request.session.set_expiry(1209600 if remember else 0)
            return redirect("home_redirect")

        error = "Invalid credentials. Please try again."

    return render(request, "login.html", {"form": form, "error": error})
