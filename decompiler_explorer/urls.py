"""decompiler_explorer URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
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

from explorer import views


router = routers.DefaultRouter()
router.register('binaries', views.BinaryViewSet, basename='binary')
router.register('binaries/(?P<binary_id>[a-f0-9-]+)/decompilations', views.DecompilationViewSet, basename='decompilation')
router.register('decompilation_requests', views.DecompilationRequestViewSet, basename='decompilationrequest')
router.register('decompilers', views.DecompilerViewSet, basename='decompiler')


urlpatterns = [
    path('', include('explorer.urls')),
    path('api/', include(router.urls)),
    path('admin/', admin.site.urls),
    path('api/queue', views.QueueView.as_view())
]
