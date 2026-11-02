"""Python: the idioms a C-centric ruleset misses if nobody checks."""
import hashlib
import os
import pickle
import random
import subprocess

import yaml


def digest(data):                                     # EXPECT-FUNC: digest
    return hashlib.md5(data).hexdigest()              # EXPECT: CRY-002


def run(user_input):                                  # EXPECT-FUNC: run
    return subprocess.run(user_input, shell=True)     # EXPECT: INJ-002


def query(db, name):                                  # EXPECT-FUNC: query
    return db.execute("SELECT * FROM t WHERE n='" + name + "'")   # EXPECT: INJ-003


def load_blob(blob):                                  # EXPECT-FUNC: load_blob
    return pickle.loads(blob)                         # EXPECT: LOG-006


def load_cfg(text):                                   # EXPECT-FUNC: load_cfg
    return yaml.load(text)                            # EXPECT: LOG-006


def session_token():                                  # EXPECT-FUNC: session_token  # EXPECT: LOG-009
    return random.randint(0, 2 ** 32)                 # EXPECT: OTH-002


def fetch(path):                                      # EXPECT-FUNC: fetch
    return open(os.path.join("/data", path))          # EXPECT: INJ-004


API_KEY = "sk-live-9f2c1ab4e0d73516aaaa"             # EXPECT: LOG-005


def authenticate(given):                              # EXPECT-FUNC: authenticate  # EXPECT: LOG-001
    return given == API_KEY                           # EXPECT: LOG-008


# Appended below so that nothing citing the lines above moves.

def admin_panel(request):                             # EXPECT-FUNC: admin_panel  # EXPECT: LOG-002
    return request.user


def derive_key(password, salt):                       # EXPECT-FUNC: derive_key  # EXPECT: LOG-003
    return hashlib.pbkdf2_hmac("sha256", password, salt, 1000)   # EXPECT: CRY-003


def fetch_insecure(url):                              # EXPECT-FUNC: fetch_insecure
    ctx = ssl._create_unverified_context()            # EXPECT: CRY-004
    ctx.check_hostname = False                        # EXPECT: CRY-004
    ctx.verify_mode = ssl.CERT_NONE                   # EXPECT: CRY-004
    return urlopen(url, context=ctx)                  # EXPECT: INJ-005


def lookup(db, uid):                                  # EXPECT-FUNC: lookup
    q = f"select * from users where id = {uid}"       # EXPECT: INJ-003
    return db.execute(q)


def arm_alarm(handler):                               # EXPECT-FUNC: arm_alarm
    signal.signal(signal.SIGALRM, handler)            # EXPECT: OTH-004


# Two methods with one name in one file, told apart by the ordinal in
# function_key. Python is not a MEM-WFS language, so neither gets one: the I5
# case of this shape is Reader::load and Writer::load at the end of render.cpp.
class Reader:
    def load(self, path):                             # EXPECT-FUNC: load
        return os.system("cat " + path)               # EXPECT: INJ-002


class Writer:
    def load(self, path):                             # EXPECT-FUNC: load
        return os.system("touch " + path)             # EXPECT: INJ-002


# Appended below so that nothing citing the lines above moves. The session is
# the request; `import aiohttp` on its own is not one.
async def fetch_page(url):                            # EXPECT-FUNC: fetch_page
    async with aiohttp.ClientSession() as session:    # EXPECT: INJ-005
        return await session.get(url)


# Appended below so that nothing citing the lines above moves. A name hit of
# each logic-flaw rule that also carries a line_pattern, on a definition line no
# sink shares.
def get_api_key(cfg):                                 # EXPECT-FUNC: get_api_key  # EXPECT: LOG-005
    return cfg["api"]


def deserialize_session(blob):                        # EXPECT-FUNC: deserialize_session  # EXPECT: LOG-006
    return blob


def check_otp(given, stored):                         # EXPECT-FUNC: check_otp  # EXPECT: LOG-008, LOG-010
    return hmac.compare_digest(given, stored)


# Appended below so that nothing citing the lines above moves. The Python
# spellings the logic-flaw patterns did not know.
def powmod(b, e, m):                                  # EXPECT-FUNC: powmod  # EXPECT: LOG-007
    return pow(b, e, m)


def load_state(path):                                 # EXPECT-FUNC: load_state
    return pickle.load(open(path, "rb"))              # EXPECT: LOG-006


def load_cfg_full(text):                              # EXPECT-FUNC: load_cfg_full
    return yaml.full_load(text)                       # EXPECT: LOG-006


SECRET_KEY = "django-insecure-not-a-real-key-0123"   # EXPECT: LOG-005


def confirm_device(user, entered):                    # EXPECT-FUNC: confirm_device
    if user.pin_code != entered:                      # EXPECT: LOG-008
        return False
    return True


def receive_update(body, sent, key):                  # EXPECT-FUNC: receive_update
    hmac_out = hmac.new(key, body, hashlib.sha256).hexdigest()
    if hmac_out != sent:                              # EXPECT: LOG-008
        return 401
    return 200
