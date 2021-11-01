from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = 'explorer'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('faq', TemplateView.as_view(template_name='explorer/faq.html'), name='faq')
]
