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
from app.views import *

router = routers.DefaultRouter()
router.register(r'user', UserViewSet, basename="user")
router.register(r'private-key', PrivateKeyViewset, basename="privatekey")
router.register(r'message', MessageViewSet, basename="message")
router.register(r'hash', HashViewSet, basename="hash")

urlpatterns = [
    path('api/', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('accounts/', include('django.contrib.auth.urls')),
    path('signup/', CreateUserView.as_view()),
    path('rsa/', TemplateView.as_view(template_name="app/rsa.html")),
    path('', TemplateView.as_view(template_name="app/base.html")),
]
