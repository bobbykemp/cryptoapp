"""cryptoapp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required
from app.views import *

router = routers.DefaultRouter()
router.register(r'user', UserViewSet, basename="user")
router.register(r'keys', PrivateKeyViewset, basename="privatekey")
router.register(r'message', MessageViewSet, basename="message")
router.register(r'hash', HashViewSet, basename="hash")
router.register(r'user-keys', UserKeysViewSet, basename="user-key")
router.register(r'sign', SignatureViewSet, basename="sign")

urlpatterns = [
    path('api/',            include(router.urls)),
    path('api_auth/',       include('rest_framework.urls', namespace='rest_framework')),
    path('signin/',         TemplateView.as_view(template_name='app/signin.html')), 
    path('signup/',         CreateUserView.as_view()),
    path('rsa/',            login_required(TemplateView.as_view(template_name="app/rsa.html"))),
    path('my-keys/',        login_required(TemplateView.as_view(template_name="app/keys.html"))),
    path('public-keys/',    login_required(TemplateView.as_view(template_name="app/key_store_card.html"))),
    path('',                TemplateView.as_view(template_name="app/base.html")),
]
