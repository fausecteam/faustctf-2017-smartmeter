from random import choice
from requests import HTTPError
import requests.exceptions
from hashlib import md5
import ssl
#try:
from ctf_gameserver.checker import BaseChecker, OK, TIMEOUT, NOTWORKING, NOTFOUND, RECOVERING
"""except ImportError:
    OK = 0
    TIMEOUT = 1
    NOTWORKING = 2
    NOTFOUND = 3
    RECOVERING = 4
    class BaseChecker:
        _ip = "127.0.0.1"
        _tick = 1
        _yaml = {}
        def get_flag(self, tick):
            assert tick > 0
            return "FAUST_01234567890ABCDEF1234567890123456789ABCDEF"
        def store_yaml(self, key, value):
            self._yaml[key] = value
        def retrieve_yaml(self, key):
            return self._yaml[key]
"""
from .provider import Provider

services = {
    "smartmeter": "kore [parent]",
    "doedel": "-java",
    "doodle": "-gst-remote",
    "toaster": "-python3",
    "tempsense": "-python3",
    "smartscale": "dbus-daemon",
    "toilet": "-nginx",
    "alexa": "-uwsgi",
}

def disable_ssl_warnings():
    import requests.packages.urllib3
    from requests.packages.urllib3 import exceptions
    requests.packages.urllib3.disable_warnings(exceptions.InsecureRequestWarning)
disable_ssl_warnings()

class SmartmeterChecker(BaseChecker):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._data = {}

    def place_flag(self):
        tick = self._tick
        provider = Provider(self._ip, self.logger)
        try:
            email, password = provider.register()

            svc = self._service_cur_tick()
            reason = self.get_flag(self._tick)
            self.logger.debug("picked service %s, user %s for tick %d / flag %s", svc, email, tick, reason)
            self.store_yaml("data-{}".format(tick), {"email": email, "pw": password, "svc": svc})
            if provider.backdoor_grant_permissions(email, svc, reason):
                return OK
            self.logger.error("backdoor not working 1")

        except (HTTPError, ValueError, ssl.SSLError):
            self.logger.exception("invalid response")
        except (ConnectionResetError, requests.exceptions.SSLError):
            return TIMEOUT
        return NOTWORKING

    def _service_cur_tick(self):
        tick = self._tick
        old_ticks = set()
        for old_tick in range(max(tick - 5, 0), tick):
            try:
                old_ticks.add(self._get_data(old_tick)[2])
            except KeyError:
                pass
        return choice(list(set(services.keys()) - old_ticks))

    def _get_data(self, tick):
        if tick not in self._data:
            self._data[tick] = self.retrieve_yaml("data-{}".format(tick))
        data = self._data[tick]
        if data is None:
            raise KeyError(tick)
        return data['email'], data['pw'], data['svc']

    def check_flag(self, tick):
        provider = Provider(self._ip, self.logger)
        try:
            email, password, svc = self._get_data(tick)
            reason = self.get_flag(tick)
            recv_flag = provider.backdoor_check_flag(svc)
            if recv_flag != reason:
                self.logger.warn("got flag '%s' instead of '%s'", recv_flag, reason)
                return NOTFOUND

            self.logger.debug("checking energy usage for service %s", svc)

            res = provider._post("usage/device_energy", data={
                'email': email,
                'password': password,
                'device': svc,
            })
            nm, load = res.text.split("\n")
            # TODO: process name does not always equal service name
            expect = services[svc]
            must_match = True
            if expect[0] == '-':
                expect = expect[1:]
                must_match = False
            if expect != nm and nm != '-offline-':
                self.logger.debug("service '%s' has weird process name '%s'", expect, nm)

            if must_match and expect != nm:
                self.logger.error("invalid response: %s for service %s", repr(nm), repr(svc))
                return NOTWORKING
            float(load)
            return OK
        except KeyError:
            self.logger.exception("flag not found")
            return NOTFOUND
        except (ValueError, HTTPError, ssl.SSLError):
            self.logger.exception("invalid response")
            return NOTWORKING
        except (ConnectionResetError, requests.exceptions.SSLError):
            return TIMEOUT

    def check_service(self):
        provider = Provider(self._ip, self.logger)
        try:
            provider._post("utility_company/get_data")
            total = provider._get("usage/total_energy")
            float(total.text)

            checksum = choice(list({
                "bootstrap-theme.min.css": "ab6b02efeaf178e0247b9504051472fb",
                "bootstrap.min.css": "ec3bb52a00e176a7181d454dffaea219",
                "bootstrap.min.js": "5869c96cc8f19086aee625d670d741f9",
                "device_energy.html": "db502c67bdeee4dc533fe6879c708c3a",
                "index.html": "884102364747505d822b329357af40d8",
                "jquery.min.js": "4f252523d4af0b478c810c2547a63e19",
                "register.html": "dc1a69e691fe7d95d7aa8c89935a9224",
            }.items()))
            resp = provider._get("static?file=" + checksum[0])
            if md5(resp.content).hexdigest() != checksum[1]:
                self.logger.warning("unexpected file contents for file '%s'", checksum[0])
                self.logger.debug("wrong contents: %s", repr(resp.content))
                return NOTWORKING

            return OK
        except (HTTPError, ValueError, KeyError, ssl.SSLError):
            self.logger.exception("invalid response")
            return NOTWORKING
        except (ConnectionResetError, requests.exceptions.SSLError):
            return TIMEOUT
