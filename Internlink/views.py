from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.db import transaction, IntegrityError

from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.cache import never_cache

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
# Small render helper: prevent wizard pages from being cached
# (Avoids stale CSRF token when user uses Back button)
# ===============================
def _render_no_store(request, template_name, context=None):
    response = render(request, template_name, context or {})
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return response


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
@never_cache
def register_start(request):
    _reg_reset(request)
    return redirect("register_role")


@never_cache
@ensure_csrf_cookie
def register_role(request):
    data = _reg_get(request)
    form = RoleSelectForm(request.POST or None, initial={"role": data.get("role")})

    if request.method == "POST" and form.is_valid():
        data["role"] = form.cleaned_data["role"]
        _reg_set(request, data)
        return redirect("register_details")

    return _render_no_store(request, "register_role.html", {"form": form, "step": 1})


@never_cache
@ensure_csrf_cookie
def register_details(request):
    data = _reg_get(request)
    role = data.get("role")

    if role not in ("STUDENT", "COMPANY"):
        return redirect("register_role")

    FormClass = StudentStepForm if role == "STUDENT" else CompanyStepForm
    form = FormClass(request.POST or None, initial=data.get("details", {}))

    if request.method == "POST" and form.is_valid():
        data["details"] = form.cleaned_data
        _reg_set(request, data)
        return redirect("register_account")

    return _render_no_store(
        request,
        "register_details.html",
        {"form": form, "role": role, "step": 2},
    )


@never_cache
@ensure_csrf_cookie
def register_account(request):
    data = _reg_get(request)
    role = data.get("role")
    details = data.get("details")

    if role not in ("STUDENT", "COMPANY") or not details:
        return redirect("register_role")

    form = AccountStepForm(request.POST or None, initial=data.get("account", {}))

    if request.method == "POST" and form.is_valid():
        username = (form.cleaned_data.get("username") or "").strip()
        email = (form.cleaned_data.get("email") or "").strip()
        phone = details.get("phone")

        # Pre-checks so we can show correct errors (not misleading)
        if User.objects.filter(username__iexact=username).exists():
            form.add_error("username", "This username is already taken.")
            return _render_no_store(request, "register_account.html", {"form": form, "step": 3})

        # Email is NOT unique by default in Django User, but your app UX expects it to be unique.
        # So we enforce it here.
        if User.objects.filter(email__iexact=email).exists():
            form.add_error("email", "This email is already registered.")
            return _render_no_store(request, "register_account.html", {"form": form, "step": 3})

        # If your Profile.phone is unique (recommended), check it too.
        if phone and Profile.objects.filter(phone=phone).exists():
            form.add_error(None, "This phone number is already registered.")
            return _render_no_store(request, "register_account.html", {"form": form, "step": 3})

        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=form.cleaned_data["password1"],
                )

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

                # Create OTP inside the transaction (so failures roll back registration)
                otp = create_or_refresh_email_otp(user, minutes_valid=10)
                otp_code = otp.code

                # Send email after commit succeeds (if email fails, user can use Resend on Step 4)
                def _safe_send():
                    try:
                        send_verification_code_email(user, otp_code)
                    except Exception:
                        pass

                transaction.on_commit(_safe_send)

            _reg_reset(request)

            request.session[VERIFY_SESSION_KEY] = user.id
            request.session.modified = True

            messages.success(request, "Account created! We sent a 6-digit verification code to your email.")
            return redirect("verify_email_code")

        except IntegrityError as e:
            # If something else caused IntegrityError (NOT NULL, DB constraint, etc.)
            # show the real reason instead of lying about username/email.
            form.add_error(None, f"Could not create account. Database error: {e}")
            return _render_no_store(request, "register_account.html", {"form": form, "step": 3})

        except Exception as e:
            form.add_error(None, f"Registration failed: {e}")
            return _render_no_store(request, "register_account.html", {"form": form, "step": 3})

    return _render_no_store(request, "register_account.html", {"form": form, "step": 3})


# ===============================
# OTP Verify + Resend
# ===============================
@never_cache
@ensure_csrf_cookie
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

    if user.is_active:
        request.session.pop(VERIFY_SESSION_KEY, None)
        messages.info(request, "Your email is already verified. Please log in.")
        return redirect("login")

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
            return _render_no_store(request, "verify_email_code.html", {"form": form, "email": user.email})

        user.is_active = True
        user.save(update_fields=["is_active"])
        otp.is_used = True
        otp.save(update_fields=["is_used"])

        request.session.pop(VERIFY_SESSION_KEY, None)

        messages.success(request, "Email verified! You can now log in.")
        return redirect("login")

    return _render_no_store(request, "verify_email_code.html", {"form": form, "email": user.email})


@never_cache
@ensure_csrf_cookie
def resend_email_code(request):
    user_id = request.session.get(VERIFY_SESSION_KEY)
    user = User.objects.filter(id=user_id).first() if user_id else None

    # Mode A: user is already in verify flow (Step 4)
    if user and not user.is_active:
        if request.method == "POST":
            otp = create_or_refresh_email_otp(user, minutes_valid=10)
            send_verification_code_email(user, otp.code)
            messages.success(request, "A new code has been sent to your email.")
            return redirect("verify_email_code")

        return _render_no_store(
            request,
            "resend_email_code.html",
            {"has_session_user": True, "email": user.email},
        )

    if user and user.is_active:
        request.session.pop(VERIFY_SESSION_KEY, None)
        messages.info(request, "Your email is already verified. Please log in.")
        return redirect("login")

    # Mode B: came from login (no session)
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip().lower()
        user2 = User.objects.filter(email__iexact=email).first()

        if user2 and not user2.is_active:
            otp = create_or_refresh_email_otp(user2, minutes_valid=10)
            send_verification_code_email(user2, otp.code)

        messages.success(request, "If the email exists and isn't verified yet, we sent a new code.")
        return redirect("login")

    prefill_email = (request.GET.get("email") or "").strip()
    return _render_no_store(
        request,
        "resend_email_code.html",
        {"has_session_user": False, "prefill_email": prefill_email},
    )


# ===============================
# Login (username / email / phone)
# ===============================
@never_cache
@ensure_csrf_cookie
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

        user = authenticate(
            request,
            username=user_obj.username,
            password=password
        ) if user_obj else None

        if user:
            if not user.is_active:
                request.session[VERIFY_SESSION_KEY] = user.id
                request.session.modified = True
                messages.info(request, "Your account isn’t verified yet. Enter the code we emailed you (or resend a new one).")
                return redirect("verify_email_code")

            login(request, user)
            request.session.set_expiry(1209600 if remember else 0)
            return redirect("home_redirect")

        error = "Invalid credentials. Please try again."

    return _render_no_store(request, "login.html", {"form": form, "error": error})
