from base64 import b16decode, b16encode
from hashlib import sha1
from Crypto.Cipher import AES
import hmac
import struct
import time
import codecs
import re
from cStringIO import StringIO
from Crypto import Random

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from AccessControl.SecurityInfo import ClassSecurityInfo
from Products.PluggableAuthService.interfaces.plugins import \
    ILoginPasswordExtractionPlugin, \
    IAuthenticationPlugin, \
    ICredentialsUpdatePlugin, \
    ICredentialsResetPlugin

from App.class_init import default__class_init__ as InitializeClass
from Products.PluggableAuthService.utils import classImplements

from zope.event import notify
try:
    from vitae.content.events import UserNeededEvent
    VITAE = True
except ImportError:
    VITAE = False

from App.config import getConfiguration
config = getConfiguration()
env = getattr(config, 'environment', {})
COOKIE_DOMAIN = env.get('COOKIE_DOMAIN', '')
COOKIE_TTL = int(env.get('COOKIE_TTL', '20'))

# so we can override for testing
def time_time():
    return time.time()

def ReadFormsAuthTicketStringV3(f):
    chars = ord(f.read(1))
    reader = codecs.getreader('utf-16le')
    r = reader(f)
    return r.read(chars)


def WriteFormsAuthTicketStringV3(f, s):
    l = len(s)
    f.write(chr(l))
    f.write(s.encode('utf-16le'))


def ReadFormsAuthTicketStringV2(f):
    reader = codecs.getreader('utf-16le')
    result = ""
    r = reader(f)
    while 1:
        c = r.read(1)
        if c == '\x00' or c is None:
            return result
        else:
            result = result + c


def WriteFormsAuthTicketStringV2(f, s):
    s = s + '\x00'
    f.write(s.encode('utf-16le'))


ReadFormsAuthTicketString = ReadFormsAuthTicketStringV3
WriteFormsAuthTicketString = WriteFormsAuthTicketStringV3


def tounixtime(t):
    return (t - 621355968000000000) / 10000000


def towintime(t):
    return (t * 10000000) + 621355968000000000


class ASPXAuthPlugin(BasePlugin):
    """ASPXAuth Plugin.

    """

    meta_type = 'ASPXAuth Plugin'
    security = ClassSecurityInfo()

    signatureLength = hmac.new(key='', digestmod=sha1).digest_size

    _properties = (
            {
                 "id": "validation_key",
                 "label": "Validation Key",
                 "type": "string",
                 "mode": "w",
             },
            {
                 "id": "decryption_key",
                 "label": "Decryption Key",
                 "type": "string",
                 "mode": "w",
             },
            )

    #cookie = """31EBBD78D6F27972394A513A161AD0362E7906830460CE7D3F44E47B2F1AF63DD43E02EB22259E4AF342B232768D6701C9395AF42448E5D149FE8AE2E4D355E9F43A9B60E1A30C0282F9ED470D8037F3B9D1D965293BED7C6156672527A94B22F24039C3F7CA6ECFF6D50A0BFFB38C0E03FF9644092FB5F8FD6E6292AA7A49B5FF603456DE4EA041F785CC163A92C34937FDE017"""
    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title
        self.validation_key = ''
        self.decryption_key = ''

    def checkSignature(self, data, sig):
        return sig == self.signData(data)

    def signData(self, data):
        validationAlgorithm = hmac.new(key=b16decode(self.validation_key), digestmod=sha1)
        validationAlgorithm.update(data)
        return validationAlgorithm.digest()

    def decryptData(self, data):
        iv = Random.new().read(AES.block_size)
        decryptionAlgorithm = AES.new(b16decode(self.decryption_key), AES.MODE_CBC, iv)
        decryptedBytes = decryptionAlgorithm.decrypt(data)
        preamblelen = len(self.decryption_key) / 2
        stream = decryptedBytes[preamblelen:]
        return stream

    def encryptData(self, data):
        preamblelen = len(self.decryption_key) / 2
        preamble = Random.new().read(preamblelen)
        data = preamble + data
        iv = Random.new().read(AES.block_size)
        encryptionAlgorithm = AES.new(b16decode(self.decryption_key), AES.MODE_CBC, iv)
        l = len(data)
        block_size = encryptionAlgorithm.block_size
        r = l % block_size
        if r == 0:
            numpad = 0
        else:
            numpad = block_size - r
        data = data + '\n' * numpad

        encryptedBytes = encryptionAlgorithm.encrypt(data)
        return encryptedBytes

    def unpackDataV3(self, data):

        stream = StringIO(data)
#        stream.read(8) # 8 bytes of random at start
        if stream.read(1) != '\x01':
            return
        version = int(ord(stream.read(1)))
        start_time = tounixtime(struct.unpack("Q", stream.read(8))[0])
        if stream.read(1) != '\xFE':
            return
        end_time = tounixtime(struct.unpack("Q", stream.read(8))[0])
        persistent = int(ord(stream.read(1)))

        username = ReadFormsAuthTicketString(stream)
        userdata = ReadFormsAuthTicketString(stream)
        path = ReadFormsAuthTicketString(stream)

        if stream.read(1) != '\xFF':
            return

        return (start_time, end_time, username, version, persistent, userdata, path)

    def unpackDataV2(self, data):
        stream = StringIO(data)
        stream.read(8)  # 8 bytes of random at start
        version = int(ord(stream.read(1)))
        username = ReadFormsAuthTicketString(stream)
        start_time = tounixtime(struct.unpack("Q", stream.read(8))[0])
        persistent = int(ord(stream.read(1)))
        end_time = tounixtime(struct.unpack("Q", stream.read(8))[0])
        userdata = ReadFormsAuthTicketString(stream)
        path = ReadFormsAuthTicketString(stream)

        if stream.read(1) != '\x00':
            return

        return (start_time, end_time, username, version, persistent, userdata, path)

    unpackData = unpackDataV3

    def decodeCookie(self, cookie):
        cookie_bytes = b16decode(cookie)
        sig = cookie_bytes[-self.signatureLength:]
        data = cookie_bytes[:-self.signatureLength]
        return sig, data

    def encodeCookie(self, data, sig):
        cookie_bytes = data + sig
        return b16encode(cookie_bytes)

    def packDataV3(self, start_time, end_time, username, version=None, persistent=None, userdata=None, path=None):
        if version is None:
            version = 2
        if persistent is None:
            persistent = 0
        if userdata is None:
            userdata = ''
        if path is None:
            path = '/'
        data = StringIO()
        data.write('\x01')  # start marker
        data.write(chr(version))  # version number
        data.write(struct.pack("<Q", towintime(start_time)))  # start time
        data.write('\xFE')  # marker
        data.write(struct.pack("<Q", towintime(end_time)))  # end time
        data.write(chr(persistent))  # persistent
        WriteFormsAuthTicketString(data, username)
        WriteFormsAuthTicketString(data, userdata)
        WriteFormsAuthTicketString(data, path)
        data.write('\xFF')

        value = data.getvalue()
        sig = self.signData(value)
        value = value + sig
        l = len(value)
        block_size = 24
        r = l % block_size
        if r == 0:
            numpad = 0
        else:
            numpad = block_size - r
        value = value + chr(numpad) * numpad

        return value

    packData = packDataV3

    def encryptCookie(self, start_time, end_time, username, version=None, persistent=None, userdata=None, path=None):
        data = self.packData(start_time, end_time, username, version, persistent, userdata, path)
        data = self.encryptData(data)
        sig = self.signData(data)
        cookie = self.encodeCookie(data, sig)
        return cookie

    security.declarePrivate('authenticateCredentials')
    def authenticateCredentials(self, credentials):

        request = self.REQUEST
        response = request.RESPONSE
        # if we already authenticated
        if request.get("AUTHENTICATED_USER", None) is not None:
            uuid = request.AUTHENTICATED_USER.getName()
            # return uuid, username ??? where is username ?
            return uuid, uuid

        # We only authenticate when our challenge mechanism extracted
        # the cookie
        if credentials.get('plugin') != self.getId():
            return None

        cookie = credentials.get('cookie')
        if not cookie:
            return None

        sig, data = self.decodeCookie(cookie)

        if not self.checkSignature(data, sig):
            return None

        decryptedBytes = self.decryptData(data)
        if not decryptedBytes:
            return None

        unpacked = self.unpackData(decryptedBytes)
        if unpacked is None:
            return None
        start_time, end_time, username, version, persistent, userdata, path = unpacked

        # Check the cookie time still valid
        t = time_time()
        if t > (start_time - 300) and t < end_time and version == 2:

            # update the cookie if we are past halfway of lifetime
            if t > start_time + ((end_time - start_time) / 2):
                self.updateCredentials(request, response, username, None)

            if not request.cookies.get('username'):
                if VITAE:
                    notify(UserNeededEvent(self, username))
                response.setCookie('username', username, quoted=False, path='/', domain=COOKIE_DOMAIN)
                request.cookies['username'] = username  # so we see it on this request also
            return username, username

    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):

        """ Extract final auth credentials from 'request'.
        """

        cookie = request.cookies.get('.ASPXAUTH')
        creds = {}
        creds['cookie'] = cookie
        creds['plugin'] = self.getId()

        return creds

    def updateCredentials(self, request, response, login, new_password):
        # another plugin tries to call this with email address (login) rather then uuid, so ignore
        if not re.match(r'^.{8}-.{4}-.{4}-.{4}-.{12}$', login):
            return

        start_time = int(time_time())
        end_time = int(start_time + (60 * COOKIE_TTL))

        cookie = self.encryptCookie(start_time, end_time, login)

        response.setCookie('.ASPXAUTH', cookie, quoted=False, path='/', domain=COOKIE_DOMAIN)

    def resetCredentials(self, request, response):
        """ Raise unauthorized to tell browser to clear credentials. """
        response.expireCookie('.ASPXAUTH', path='/', domain=COOKIE_DOMAIN)
        response.expireCookie('username', path='/', domain=COOKIE_DOMAIN)


classImplements(ASPXAuthPlugin,
                IAuthenticationPlugin,
                ILoginPasswordExtractionPlugin,
                ICredentialsUpdatePlugin,
                ICredentialsResetPlugin)

InitializeClass(ASPXAuthPlugin)
