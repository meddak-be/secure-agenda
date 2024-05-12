
from django.db import models
from django.urls import reverse 
from django.contrib.auth.models import User

import uuid

class Event(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="event", null=True)
    title = models.CharField(max_length=500)
    description = models.TextField()
    location = models.TextField(max_length=500, default="No location specified")
    start_time = models.TextField(max_length=500)
    end_time = models.TextField(max_length=500)
    @property
    def get_html_url(self):
        url = reverse('event_edit', args=(self.id,))
        return f'<a href="{url}"> {self.title} </a>'

class FriendRequest(models.Model):
    sender = models.ForeignKey('auth.User',on_delete=models.CASCADE,related_name='friend_requests_sent')
    recipient = models.ForeignKey('auth.User',on_delete=models.CASCADE,related_name='friend_requests_received')
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, default='pending')

class EventRequest(models.Model):
    sender = models.ForeignKey('auth.User',on_delete=models.CASCADE,related_name='event_requests_sent')
    recipient = models.ForeignKey('auth.User',on_delete=models.CASCADE,related_name='event_requests_received')
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="event_inv")
    status = models.CharField(max_length=10, default='pending')

class EventSymKey(models.Model):
    user = models.ForeignKey('auth.User',on_delete=models.CASCADE,related_name='invited_user')
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="event")
    key = models.CharField(max_length=500)

class EventSignature(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="event_sign")
    signature = models.CharField(max_length=500)

class PublicKeys(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="public_key")
    key = models.CharField(max_length=500)
    signed_key = models.CharField(max_length=500)
    salt = models.CharField(max_length=500)

class RequestsNewDev(models.Model):
    ip_address = models.CharField(primary_key=True, max_length=10)
    browser = models.CharField(max_length=100)
    status = models.CharField(max_length=10, default='pending')
    public_key = models.CharField(max_length=500, default='null', null=True) # public key of the new device
    dest_user = models.ForeignKey('auth.User', on_delete=models.CASCADE, related_name="access_dev")
    private_key_usr = models.CharField(max_length=500, default='null') # encrypted with the public key of the new device
    salt_user = models.CharField(max_length=100, blank=True)

class BlockIPs(models.Model):
    ip_address = models.CharField(primary_key=True, max_length=10)
    permanent = models.BooleanField(default=False)
    time = models.IntegerField(default=0)