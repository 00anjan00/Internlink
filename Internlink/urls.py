from django.urls import path
from . import views

urlpatterns = [
    path("", views.landing, name="landing"),
    path("login/", views.login_page, name="login"),
    path("logout/", views.logout_view, name="logout"),

    path("home/", views.home_redirect, name="home_redirect"),
    path("student/", views.student_home, name="student_home"),
    path("company/", views.company_home, name="company_home"),
    path("register/", views.register_start, name="register"),
    path("register/role/", views.register_role, name="register_role"),
    path("register/details/", views.register_details, name="register_details"),
    path("register/account/", views.register_account, name="register_account"),
    path("verify-email/", views.verify_email_code, name="verify_email_code"),
    path("resend-code/", views.resend_email_code, name="resend_email_code"),
]
