from datetime import datetime, timedelta, date
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.views import generic
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError

from .forms import RegisterForm, LoginForm, SettingForm

import calendar

from logtail import LogtailHandler
import logging 

from .models import *
from .forms import EventForm
from .forms import FriendRequestForm
from .firewall import add_ip_to_blocked_list

import json
import pyotp
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64
import time

# CONSTANTS
ATTEMPT_LOGIN_THRESHOLD = 5
ATTEMPT_SPAM_THRESHOLD = 150
TIME_BAN_LOGIN = 30*60
TIME_BAN_SPAM = 1*60

attempts_login = {}
attempts_spam = {}

handler = LogtailHandler(source_token="AruhADRqUsWQNcw6MMRXyU5o")

logger = logging.getLogger(__name__)
logger.handlers = []
logger.setLevel(logging.INFO)
logger.addHandler(handler)

#logging methods to write info and ban logs

def writeInfoLog(request):
    logger.info("{0} from {1}".format(request.path, request.META['REMOTE_ADDR']),extra={
        'ip_address': request.META['REMOTE_ADDR'],
        'browser': request.META['HTTP_USER_AGENT'],
        'path':request.path,
        'method':request.method,
        'username':request.user.username
    })

def writeBanLog(ip_address):
    logger.warning('ip {0} has been banned temporarily'.format(ip_address), extra={
        'ip_address': ip_address
    })

def writePermanentBanLog(ip_address):
    logger.warning('ip {0} has been banned permanently'.format(ip_address), extra={
        'ip_address': ip_address
    })

def writeUnauthorizedAccess(ip_address, path):
    logger.warning('ip {0} tried to access to an unauthorized ressource {1}'.format(ip_address, path), extra={
        'ip_address': ip_address,
        'path': path
    })

#checks if a user is spamming and ban him if it is the case 
def spam_check(ip_address):
    if ip_address not in attempts_spam:
        attempts_spam[ip_address] = {"SPAM":[time.time(), 1]}
    elif "SPAM" not in attempts_spam[ip_address]:
        attempts_spam[ip_address] = {"SPAM":[time.time(), 1]}
    else:
        time_attempt = (time.time() - attempts_spam[ip_address]["SPAM"][0])
        if time_attempt > TIME_BAN_SPAM and attempts_spam[ip_address]["SPAM"][1] >= ATTEMPT_SPAM_THRESHOLD:
            add_ip_to_blocked_list(ip_address, permanent=True)
            writePermanentBanLog(ip_address)
            del attempts_spam[ip_address]
        elif time_attempt > TIME_BAN_SPAM:
            attempts_spam[ip_address]["SPAM"] = [time.time(), 1]
        else:
            if attempts_spam[ip_address]["SPAM"][1] >= ATTEMPT_SPAM_THRESHOLD:
                add_ip_to_blocked_list(ip_address, permanent=True)
                writePermanentBanLog(ip_address)
                del attempts_spam[ip_address]
            else:
                attempts_spam[ip_address]["SPAM"][1] += 1

class CalendarView(generic.ListView):
    model = Event
    template_name = 'agendaApp/calendar.html'
    context_object_name = 'events'
    
    
    def get_context_data(self, **kwargs):
        #log
        writeInfoLog(self.request)
        spam_check(self.request.META['REMOTE_ADDR'])
        #retrieve all the events that the user created or has been invited to to show them in the list
        if (self.request.user.is_authenticated):
            context = super().get_context_data(**kwargs)
            context['events'] = Event.objects.filter(user=self.request.user)
            invitations = EventRequest.objects.filter(recipient=self.request.user, status="accepted")
            context['invited_events'] = Event.objects.filter(pk__in=[invitation.event.pk for invitation in invitations])

            for cont in [context['events'], context['invited_events']]:
                for event in cont:
                    key = EventSymKey.objects.get(event=event, user=self.request.user)
                    event.symKey = key.key
                    pubKey = PublicKeys.objects.get(user=event.user_id)
                    event.creatorPubKey = pubKey.key
                    signature = EventSignature.objects.get(event=event) 
                    event.signature = signature.signature  

            return context

        else:
            return None

def event(request, event_id=None):
    if str(request.user) == "AnonymousUser":
        writeUnauthorizedAccess(request.META['REMOTE_ADDR'], request.path)
        return HttpResponse('Unauthorized', status=401)
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])
    instance = Event()
    invitedFriendEvent = []
    friends_list = []
    symKey="None"
    if event_id:
        #event retrieval
        e = Event.objects.get(id=event_id)
        symKey = EventSymKey.objects.get(user=request.user, event=e)
        symKey = symKey.key
        instance = get_object_or_404(Event, pk=event_id)
        #user retrieval
        user = request.user
            #friend retrieval
        friends = FriendRequest.objects.filter(sender=user, status='accepted') | FriendRequest.objects.filter(recipient=user, status='accepted')
        for elem in friends:
            if elem.sender == user:
                friends_list.append(elem.recipient)
            else:
                friends_list.append(elem.sender)
        #removal of friends already invited to the event
        invitedFriendEvent = EventRequest.objects.filter(event=e, sender=user, status="accepted") | EventRequest.objects.filter(event=instance, sender=user, status="pending")
        for elem in invitedFriendEvent:
            if elem.recipient in friends_list:
                friends_list.remove(elem.recipient)
        #get the public keys - in order to encrypt the symmetric key if invited
        for friend in friends_list:
            friendPubKey = PublicKeys.objects.get(user=friend)
            friend.pub_key = friendPubKey.key
        
        #if the user is not the owner of the event, only show the details - no possibility to edit
        if e not in request.user.event.all():
            events = EventRequest.objects.filter(event=instance, recipient=user, status="accepted")
            
            if len(events) == 1:
                symKey = EventSymKey.objects.get(user=user, event=instance)
                return render(request, 'agendaApp/event_show.html', {'event':instance, 'sym_key':symKey.key, 'user':request.user})
            else:
                return HttpResponseRedirect(reverse('calendar'))   
    else:
    #creation of a new event
        instance = Event()

    
    instance.user = request.user

    form = EventForm(request.POST or None, instance=instance)
    if request.POST and form.is_valid():
        #save to the database and return to calendar
        ev = form.save()
        if not event_id:
            #save the symmetric key for the creator
            eventSymKey = EventSymKey.objects.create(
                user = request.user,
                key = request.POST.get('symKey'),
                event = ev
            )
            eventSymKey.save()
            #save the signature
            sign = EventSignature.objects.create(
                event = ev,
                signature = request.POST.get('signedEvent')
            )
            sign.save()
        else:
            #edit the signature if the event has been edited
            sign = EventSignature.objects.get(event=ev)
            sign.signature = request.POST.get('signedEvent')
            sign.save()
        return HttpResponseRedirect(reverse('calendar'))
    
    return render(request, 'agendaApp/event.html', {'form': form, 'friends':friends_list, 'event_id':event_id, 'friends_inv': invitedFriendEvent, 'user':request.user, 'sym_key':symKey})
    
def register(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            try:
                #save the user
                user = form.save()
                #get the key from the form
                key = request.POST.get('key')
                signedKey = request.POST.get('signed_key')
                #save the user public key
                pubKey = PublicKeys.objects.create(
                    user = user,
                    key = key,
                    signed_key = signedKey,
                    salt=request.POST.get('salt')
                )
                pubKey.save()
            except IntegrityError:
                form = RegisterForm() #generate the form
                return render(request, "register/register.html", {"form":form})

        else:
            form = RegisterForm() #generate the form
            return render(request, "register/register.html", {"form":form})
        #redirect to the login page
        return HttpResponseRedirect(reverse('login'))
    else:
        form = RegisterForm() #generate the form

    return render(request, "register/register.html", {"form":form})

def contact(request):
    if str(request.user) == "AnonymousUser":
        writeUnauthorizedAccess(request.META['REMOTE_ADDR'], request.path)
        return HttpResponse('Unauthorized', status=401)
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])
    user = request.user
    if request.method == "POST":
        #removes the friend 
        friend = request.POST["friend"]
        friend_to_remove = FriendRequest.objects.filter(sender=user, recipient=friend, status='accepted') | FriendRequest.objects.filter(sender=friend, recipient=user, status='accepted')
        friend_to_remove.delete()

    #friends retrieval
    friends = FriendRequest.objects.filter(sender=user, status='accepted') | FriendRequest.objects.filter(recipient=user, status='accepted')

    friends_list = []

    for elem in friends:
        if elem.sender == user:
            friends_list.append(elem.recipient)
        else:
            friends_list.append(elem.sender)

    #friend requests retrieval
    friend_requests = FriendRequest.objects.filter(recipient=user, status='pending')

    return render(request, "agendaApp/contact.html", {'friends_list': friends_list, 'friend_requests': len(friend_requests)})

def view_friend_requests(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])
    if request.method == "POST":
        id_request = request.POST["request"]
        if "accept_btn" in request.POST:
            #change the status of the request to accepted if the accept button is pressed and save it 
            request_to_accept = FriendRequest.objects.get(pk=int(id_request))
            request_to_accept.status = 'accepted' # add friend to friendList
            request_to_accept.save()
        elif "decline_btn" in request.POST:
            #delete the request if the decline button is pressed 
            request_to_accept = FriendRequest.objects.get(pk=int(id_request))
            request_to_accept.delete()
    user = request.user
    friend_requests = FriendRequest.objects.filter(recipient=user, status='pending')
    #shows the friend request page with the pending requests
    return render(request, 'agendaApp/friend_requests.html', {'friend_requests': friend_requests})

def send_friend_request(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])
    if request.method == 'POST':
        form = FriendRequestForm(request.POST)
        #if the form is valid and the request not already in the database, create the requests
        if form.is_valid():
            try:
                recipient = User.objects.get(username=form.cleaned_data['recipient'])
                if FriendRequest.objects.filter(sender=request.user, recipient=recipient).count() == 0 and request.user != recipient:
                    friend_request = FriendRequest.objects.create(
                        sender=request.user,
                        recipient=recipient
                    )
                    friend_request.save()

            except:
                pass # user entered does not exists
            return redirect('contact/')
    else:
        form = FriendRequestForm()
    #return the form for the friend request
    return render(request, 'agendaApp/send_friend_request.html', {'form': form})

def delete_event(request):
    if request.method == 'POST':
        #delete the event - everything related to it is also deleted
        event_id = request.POST.get('event_id')
        event = Event.objects.get(id=event_id)
        event.delete()
    return HttpResponseRedirect(reverse('calendar'))

def invite_event(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])
    if request.method == 'POST':
        #friend and event retrieval
        friend_id = request.POST.get('friend_id')
        friend = User.objects.get(id=friend_id)
        event_id = request.POST.get('event_id')
        event = Event.objects.get(id=event_id)
        encryptedSymKey = request.POST.get('symKey')
        #creation of the invitation object
        invitation = EventRequest.objects.create(
                        sender=request.user,
                        recipient=friend,
                        event=event
                    )
        
        #save it to the database
        invitation.save()
        eventSymKey = EventSymKey.objects.create(
            user=friend,
            event=event,
            key=encryptedSymKey
        )
        eventSymKey.save()
        #redirection from where it came (calendar)
        return HttpResponseRedirect(request.META.get('HTTP_REFERER'))
    else:
        return HttpResponseRedirect(reverse('calendar'))

def view_event_requests(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])
    if request.method == "POST":
        #request id retrieval
        id_request = request.POST["request"]
        if "accept_btn" in request.POST:
            #change the status of the request to accepted if the accept button is pressed and save it 
            request_to_accept = EventRequest.objects.get(pk=int(id_request))
            request_to_accept.status = 'accepted' 
            request_to_accept.save()
        elif "decline_btn" in request.POST:
            #delete the request if the decline button is pressed 
            request_to_accept = EventRequest.objects.get(pk=int(id_request))
            request_to_accept.delete()
    user = request.user
    event_requests =  EventRequest.objects.filter(recipient=user, status='pending')   
    #shows the event request page with the pending requests
    return render(request, 'agendaApp/event_requests.html', {'event_requests': event_requests})

def login_view(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])

    ip_address = request.META['REMOTE_ADDR']
    
    messages = []

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        #authenticate the user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            request.session["username"] = username
            return redirect('verification')
        else:
            #checks someone is spamming the login
            if ip_address in attempts_login and "LOGIN" in attempts_login[ip_address]:
                time_first_attempt = (time.time() - attempts_login[ip_address]["LOGIN"][0])
                if time_first_attempt > TIME_BAN_LOGIN and attempts_login[ip_address]["LOGIN"][1] >= ATTEMPT_LOGIN_THRESHOLD:
                    add_ip_to_blocked_list(ip_address, time=time.time())
                    writeBanLog(ip_address)
                    attempts_login[ip_address]["LOGIN"] = [time.time(), 1]
                elif time_first_attempt > TIME_BAN_LOGIN:
                    attempts_login[ip_address]["LOGIN"] = [time.time(), 1]
            else:
                attempts_login[ip_address] = {"LOGIN":[time.time(), 1]}
            if ip_address in attempts_login:
                if attempts_login[ip_address]["LOGIN"][1] >= ATTEMPT_LOGIN_THRESHOLD:
                    add_ip_to_blocked_list(ip_address, time=time.time())
                    writeBanLog(ip_address)
                    attempts_login[ip_address]["LOGIN"] = [time.time(), 1]
                else:
                    attempts_login[ip_address]["LOGIN"][1] += 1
            else:
                attempts_login[ip_address] = {"LOGIN":[time.time(), 1]}
            form = LoginForm()
            # Return an 'invalid login' error message.
            messages.append("Invalid credentials, please try again")
            return render(request, 'registration/login.html', {"form":form, "messages":messages}) # add error message
    else:
        # Render the login form.
        form = LoginForm()
        return render(request, 'registration/login.html', {"form":form, "messages":messages})

def logout_view(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])

    logout(request)
    return redirect('login')

def setting_view(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])

    messages = []
    if request.method == 'POST':
        old_password = request.POST['old_password']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password != confirm_password:
            form = SettingForm()
            messages.append("Invalid credentials, please try again")
            # Return an 'invalid login' error message.
            return render(request, 'registration/settings.html', {"form":form, "messages":messages}) 
        user = authenticate(request, username=request.user.username, password=old_password)
        #check the validity of the old password. If ok, change password
        if user is not None:
            request.user.set_password(password)
            request.user.save()
            form = SettingForm()
            return render(request, 'registration/settings.html', {"form":form, "messages":messages}) 
        else:
            messages.append("Invalid old password, please try again")
            form = SettingForm()
            # Return an 'invalid login' error message.
            return render(request, 'registration/settings.html', {"form":form, "messages":messages}) 
    else:
        # Render the login form.
        form = SettingForm()
        return render(request, 'registration/settings.html', {"form":form, "messages":messages})

def access_devices(request):
    if str(request.user) == "AnonymousUser":
        writeUnauthorizedAccess(request.META['REMOTE_ADDR'], request.path)
        return HttpResponse('Unauthorized', status=401)
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])

    if request.method == 'POST':
        ip_request = request.POST["request"]
        if request.POST.get('status_info') == "accepted":
            try:
                #get the request object and update its status
                request_to_accept = RequestsNewDev.objects.get(ip_address=ip_request)
                request_to_accept.status = 'accepted'
                # give the private key and the salt
                private_key = request.POST.get('private_key')
                salt = request.POST.get('salt_user')
                request_to_accept.private_key_usr = private_key
                request_to_accept.salt_user = salt
                request_to_accept.save()
            except RequestsNewDev.DoesNotExist: 
                pass # if the user reload the page and the previous request was a POST
        elif request.POST.get('status_info') == "declined":
            try:
                #delete the request object
                request_to_accept = RequestsNewDev.objects.get(ip_address=ip_request)
                request_to_accept.delete()
            except RequestsNewDev.DoesNotExist:
                pass
    user = request.user
    device_requests = RequestsNewDev.objects.filter(dest_user=user, status='pending')
    return render(request, 'registration/access.html', {'access_requests': device_requests, 'username':request.user.username, 'access_requests_size': len(device_requests)})

def access_request(request):
    writeInfoLog(request)
    spam_check(request.META['REMOTE_ADDR'])

    username = request.session['username']
    if request.method == 'POST':
        #save to the database
        user = User.objects.get(username=username)
        #get or create a request_new_dev object for the new request
        try:
            request_new_dev = RequestsNewDev.objects.get(ip_address=request.META['REMOTE_ADDR'])
            request_new_dev.public_key = request.POST.get('tmp_key') # update the key if the request already exists
            request_new_dev.status = "pending"
            request_new_dev.save()
        except RequestsNewDev.DoesNotExist:
            request_new_dev = RequestsNewDev.objects.create(
                ip_address = request.META['REMOTE_ADDR'],
                browser = request.META['HTTP_USER_AGENT'],
                status = "pending",
                public_key = request.POST.get('tmp_key'),
                dest_user = user
            )
            request_new_dev.save()
        request.session['access_requested'] = True
        #return the waiting page
        return render(request, 'registration/request_pending.html', {'access': "pending", "username": username, 'pivateKey': "null", 'publicKey': "null"})
    elif request.session.get('access_requested') and request.session['access_requested'] == "Finish":
        #the request is finished, the request object deleted
        del request.session['access_requested']
        request_new_dev = RequestsNewDev.objects.get(ip_address=request.META['REMOTE_ADDR'])
        request_new_dev.delete()
        return redirect('login')
    elif request.session.get('access_requested') and request.session['access_requested'] == True: # refresh and see if the request is accepted
        access = "pending"
        request_new_dev = RequestsNewDev.objects.filter(ip_address=request.META['REMOTE_ADDR'])
        if len(request_new_dev) == 0: # request deleted by the original user
            del request.session['access_requested']
            return redirect('login')
        private_key = ""
        public_key = ""
        salt = ""
        if request_new_dev.first().status == "accepted":
            #when the request is accepted, the data are transmitted 
            access = "accepted"
            private_key = request_new_dev.first().private_key_usr
            salt = request_new_dev.first().salt_user
            user = User.objects.get(username=username)
            public_key = PublicKeys.objects.get(user=user)
            public_key = public_key.key
            request.session['access_requested'] = "Finish"
        return render(request, 'registration/request_pending.html', {'access': access, "username": username, 'private_key': private_key, 'public_key': public_key, 'salt_user':salt})
    else:
        user = User.objects.get(username=username)
        public_key = PublicKeys.objects.get(user=user)
        return render(request, 'registration/request_access.html', {'username':username,'public_key':public_key.key})

# zero-knowledge proof to see if the client has the private key of the username and password he gave
def verification_OTP(request):
    writeInfoLog(request) # send log
    spam_check(request.META['REMOTE_ADDR']) # check if the ip spams

    username = request.session['username']
    if request.session.get('new_dev') and request.session['new_dev'] == True:
        del request.session['new_dev']
        return redirect('access_request')
    encrypted_otp = ""
    # processing otp sent by the javascript
    if request.method == 'POST':
        data = json.loads(request.body)
        message = data['message']
        if message == request.session['otp']:
            user = User.objects.get(username=username)
            login(request, user)
            return redirect('calendar')
        else: # client does not have the private key, he will be able to send an access request
            request.session['new_dev'] = True
    else:
        user = User.objects.get(username=username)

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        otp1 = totp.now()
        orp2 = totp.now()
        otp = str(otp1)+str(orp2)
        request.session['otp'] = otp

        # encrypt otp with the user's public key
        publicKey = PublicKeys.objects.get(user=user)
        rsa_key = RSA.importKey(publicKey.key) 
        cipher = PKCS1_v1_5.new(rsa_key)
        encrypted_otp = cipher.encrypt(otp.encode())
        encrypted_otp = base64.b64encode(encrypted_otp)
        encrypted_otp = encrypted_otp.decode()

    return render(request, 'registration/verification.html', {'otp':encrypted_otp,'username':username})