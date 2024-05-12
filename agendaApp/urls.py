from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^calendar/$', views.CalendarView.as_view(), name='calendar'),
    re_path(r'^event/new/$', views.event, name='event_new'),
	re_path(r'^event/edit/(?P<event_id>[0-9a-f-]+)/$', views.event, name='event_edit'),
    re_path(r'register/', views.register, name="register"),
    re_path(r'login/', views.login_view, name="login"),
    re_path(r'logout/', views.logout_view, name='logout'),
    re_path(r'settings/', views.setting_view, name='settings'),
    re_path(r'verification/', views.verification_OTP, name="verification"),
    re_path(r'access_request/', views.access_request, name="access_request"),
    re_path(r'access_devices/', views.access_devices, name="access_devices"),
    re_path(r'contact/', views.contact, name="contact"),
    re_path(r'send_friend_request/', views.send_friend_request, name="send_friend_request"),
    re_path(r'friend_requests/', views.view_friend_requests, name="friend_requests"),
    re_path(r'invite_event/', views.invite_event, name="invite_event"),
    re_path(r'delete_event/', views.delete_event, name="delete_event"),
    re_path(r'event_requests/', views.view_event_requests, name="event_requests"),
]