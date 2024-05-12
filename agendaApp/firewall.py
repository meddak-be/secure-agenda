from django.http import HttpResponse
from .models import BlockIPs

import threading, time

TIME_BAN_LOGIN = 30*60

_blocked_ips_lock = threading.Lock()

def initializeIPTemp():
    blocked_ips_temporary = []
    ips = BlockIPs.objects.all()
    for ip in ips:
        if ip.permanent == False and (time.time() - float(ip.time)) < TIME_BAN_LOGIN:
            blocked_ips_temporary.append(ip.ip_address)
        elif ip.permanent == False:
            ip.delete()
    return blocked_ips_temporary

def initializeIPs():
    blocked_ips = []
    blocked_ips_temporary = []
    ips = BlockIPs.objects.all()
    for ip in ips:
        if ip.permanent == True:
            blocked_ips.append(ip.ip_address)
        else:
            if (time.time() - float(ip.time)) < TIME_BAN_LOGIN:
                blocked_ips_temporary.append(ip.ip_address)
            else:
                ip.delete()
    return blocked_ips, blocked_ips_temporary

_blocked_ips, _blocked_ips_temporary = initializeIPs()


class BlockIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        global _blocked_ips, _blocked_ips_temporary

        _blocked_ips_temporary = initializeIPTemp()
        if request.META['REMOTE_ADDR'] in _blocked_ips:
            return HttpResponse("Your IP address has been blocked", status=403)
        elif request.META['REMOTE_ADDR'] in _blocked_ips_temporary:
            return HttpResponse("Your IP address has been temporarily blocked for 30 minutes after several login attempts", status=403)
        response = self.get_response(request)
        return response

def add_ip_to_blocked_list(ip, permanent=False, time=0):
    global _blocked_ips, _blocked_ips_temporary
    with _blocked_ips_lock:
        if ip not in _blocked_ips and ip not in _blocked_ips_temporary:
            ip_to_block = BlockIPs.objects.create(
                ip_address=ip,
                permanent=permanent,
                time=time
            )
            ip_to_block.save()
            _blocked_ips, _blocked_ips_temporary = initializeIPs()