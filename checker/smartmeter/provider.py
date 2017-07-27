import string
import os, os.path
from binascii import hexlify, unhexlify
from random import shuffle, choice, shuffle, random, sample
from ssl import SSLError

import requests

from .schnorr import Schnorr

names = [u'Balfour', u'John', u'Lemal', u'Kawasaki', u'Vigor', u'Dalston', u'Dhiman', u'Diego', u'Pavyer', u'Bainter', u'Gerius', u'Jemima', u'Vardon', u'Amalbergas', u'Cleodell', u'Erlene', u'Ransell', u'Harmon', u'Ronica', u'Urian', u'Harrow', u'Amby', u'Gausman', u'Cand', u'Gennie', u'Nero', u'Sonia', u'Jadwiga', u'Uria', u'Down', u'Poppy', u'Maddock', u'Applegate', u'Lyda', u'Idden', u'Thirzi', u'Tor', u'Fagen', u'Harts', u'Bloem', u'Fornof', u'Lull', u'Leatri', u'Astraea', u'Conlen', u'Buchheim', u'Dorcus', u'Newmann', u'Luht', u'Maunsell', u'Koloski', u'Tjon', u'Calhoun', u'Netty', u'Gottfried', u'Gorman', u'Sacksen', u'Coriss', u'Gabey', u'Gruver', u'Serafine', u'Pet', u'Maurilla', u'Bray', u'Lathrope', u'Osugi', u'Gresham', u'Arabele', u'Leacock', u'Buyse', u'Naima', u'Tami', u'Zoara', u'Anatollo', u'Timmi', u'Ticon', u'Ulrika', u'Dekeles', u'Su', u'Parfitt', u'Broddy', u'Amandy', u'Brittnee', u'Sihon', u'Elisabeth', u'Warfeld', u'Hagan', u'Nehemiah', u'Kaycee', u'Alanson', u'Endo', u'Dannica', u'Nolita', u'Hearsh', u'Walburga', u'Diella', u'Caressa', u'Elliott', u'Oglesby']


class Provider:
    #schnorr = Schnorr( b"smartmeter/privkey_rfc5114.pem")
    schnorr = Schnorr(os.path.join(os.path.dirname(__file__), "privkey_rfc5114.pem").encode())

    def __init__(self, host, logger):
        self.session = requests.Session()
        self.logger = logger
        self.url = "https://{}:2443/".format(host)

    def _get(self, path, **kwargs):
        r = self.session.get(self.url + path, verify=False, **kwargs)
        self.logger.info("GET %s%s --> %d", self.url, path, r.status_code)
        r.raise_for_status()
        return r
    def _post(self, path, throw=True, **kwargs):
        r = self.session.post(self.url + path, verify=False, **kwargs)
        #self.logger.info("POST %s%s %s --> %d", self.url, path, kwargs.get('data'), r.status_code)
        self.logger.info("POST %s%s --> %d", self.url, path, r.status_code)
        if throw:
            r.raise_for_status()
        return r

    def backdoor_grant_permissions(self, email, service, reason):
        return self._backdoor(email=email, device=service, reason=reason)

    def backdoor_check_flag(self, service):
        res = self._backdoor().get(service)
        return res[1]

    def _backdoor(self, **extra):
        challenge = unhexlify(self._get("utility_company/get_data").content)
        extra["chall"] = hexlify(challenge).decode()

        if random() > .3:
            valid = False
            mod = b"" if valid else b"invalid"
            signature = self.schnorr.sign_value(challenge + mod)
            extra["sig"] = hexlify(signature).decode()
            res = self._post("utility_company/get_data", throw=False, data=extra)
            if not res.ok or len(res.content) != 32 or b"," in res.content:
                raise ValueError("broken signature check 1")

        for i in range(100):
            valid = random() > .2 or i == 99
            mod = b"" if valid else b"invalid"
            signature = self.schnorr.sign_value(challenge + mod)
            extra["sig"] = hexlify(signature).decode()
            res = self._post("utility_company/get_data", throw=False, data=extra)
            if res.ok:
                if len(res.content) == 32 and b"," not in res.content:
                    extra["chall"] = res.content
                    challenge = unhexlify(res.content)
                    continue

                if not valid:
                    raise ValueError("broken signature check 2")
                data = (l.split(",") for l in res.text.strip().split("\n"))
                return {d[1]: (int(d[0]), d[2]) for d in data}
            elif valid:
                self.logger.warn("valid signature was not accepted. server said: %s", res.content)
        raise ValueError("broken signature check 3")

    def register(self):
        name = choice(names)
        subd = "".join(sample(string.ascii_lowercase * 31, 50-len(name)-13))
        email = name + "@" + subd + ".faust.ninja"
        password = "".join(sample(string.ascii_lowercase * 30, 30))
        res = self._post("register", data={
            "email": email,
            "password": password,
            "password_confirm": password,
        })
        return email, password

