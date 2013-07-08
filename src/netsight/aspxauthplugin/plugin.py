from base64 import b16decode, b16encode
from hashlib import sha1
from Crypto.Cipher import AES
import hmac
import struct
import time

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from AccessControl.SecurityInfo import ClassSecurityInfo
from Products.PluggableAuthService.interfaces.plugins import \
    ILoginPasswordExtractionPlugin, \
    IAuthenticationPlugin, \
    ICredentialsUpdatePlugin, \
    ICredentialsResetPlugin

from App.class_init import default__class_init__ as InitializeClass
from Products.PluggableAuthService.utils import classImplements


class ASPXAuthPlugin( BasePlugin ):
    """ASPXAuth Plugin.

    """

    meta_type = 'ASPXAuth Plugin'
    security = ClassSecurityInfo()

    signatureLength = hmac.new(key='',digestmod=sha1).digest_size
    salt = "0000000000000000"

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

    def __init__( self, id, title=None ):
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
        decryptionAlgorithm = AES.new(b16decode(self.decryption_key), AES.MODE_CBC, self.salt)
        decryptedBytes =  decryptionAlgorithm.decrypt(data)
        stream = decryptedBytes[32:]
        if ord(stream[0]) == 1:
            return stream

    def encryptData(self, data):
        encryptionAlgorithm = AES.new(b16decode(self.decryption_key), AES.MODE_CBC, self.salt)
        l = len(data)
        r = l % 32
        if r == 0:
            numpad = 0
        else:
            numpad = 32 - r
        data = '\0' * 16 + data + '\n' * numpad

        encryptedBytes =  encryptionAlgorithm.encrypt(data)
        return self.salt + encryptedBytes

    def unpackData(self, data):
        version = int(ord(data[1]))
        start_time = (struct.unpack("Q", data[2:2+8])[0] - 621355968000000000) / 10000000
        end_time = (struct.unpack("Q", data[2+8+1:2+8+8+1])[0] - 621355968000000000) / 10000000
        username = (data[2+8+8+1+2:].split('\x00\x00')[0]+'\0').decode('utf16')
        return (version, start_time, end_time, username)

    def decodeCookie(self, cookie):
        cookie_bytes = b16decode(cookie)
        sig = cookie_bytes[-self.signatureLength:]
        data = cookie_bytes[:-self.signatureLength]
        return sig, data

    def encodeCookie(self, data, sig):
        cookie_bytes = data + sig
        return b16encode(cookie_bytes)

    def packData(self, version, start_time, end_time, username):
        data = struct.pack("<BBQBQ", 1, version, (start_time*10000000) + 621355968000000000, 254, (end_time*10000000) + 621355968000000000)
        data = data + '\0' + '\x14' + ('%s' % username).encode('utf-16le') + '\0'
        return data

    def encryptCookie(self, version, start_time, end_time, username):
        data = self.packData(version, start_time, end_time, username)
        data = data[:-1]
        data = data + '\x01/\x00\xff\xfa\xaa"\xb0\x93n\xdft\xa9\x94\xb6\xb3%**\x1aW5\xc0b'
        data = self.encryptData(data)
        sig = self.signData(data)
        cookie = self.encodeCookie(data, sig)
        return cookie

    security.declarePrivate( 'authenticateCredentials' )
    def authenticateCredentials( self, credentials ):

        # We only authenticate when our challenge mechanism extracted
        # the cookie
        if credentials.get('plugin') != self.getId():
            return None

        cookie = credentials.get('cookie')
        if not cookie:
            return None

        #validation_key = """07B6387D1DED6BF193EDD726B4ADFD6B92EDA470DDF639D4B78110CA797DCED426BECF322B9FBCC5E7C3FDA2E7BA28169611B1ACD1E7F063ABF17ECDC30AD482"""
        #decryption_key = """CFE45C8F9D17D68B71DAB98158E1F78E5AC05D6C5A7184BD1BF26E6E36FA5973"""

        sig, data = self.decodeCookie(cookie)

        if not self.checkSignature(data,sig):
            return None

        decryptedBytes = self.decryptData(data)
        if not decryptedBytes:
            return None
        
        version, start_time, end_time, username = self.unpackData(decryptedBytes)        

        # Check the cookie time still valid
        t = time.time()
        if 1 or t > start_time and t < end_time and version == 2:
            return username, username        

    security.declarePrivate( 'extractCredentials' )
    def extractCredentials( self, request ):

        """ Extract final auth credentials from 'request'.
        """

        cookie = request.cookies.get('.ASPXAUTH')
        creds = {}
        creds['cookie'] = cookie
        creds['plugin'] = self.getId()

        return creds

    def updateCredentials(self, request, response, login, new_password):
        version = 2
        start_time = int(time.time())
        end_time = int(start_time + (60 * 20) )

        cookie = self.encryptCookie(version, start_time, end_time, login)
        
        response.setCookie('.ASPXAUTH', cookie, quoted=False, path='/', domain='.vitaeplone.netsightdev.co.uk')

    def resetCredentials(self, request, response):
        """ Raise unauthorized to tell browser to clear credentials. """
        response.expireCookie('.ASPXAUTH', path='/', domain='.vitaeplone.netsightdev.co.uk')        


classImplements(ASPXAuthPlugin,
                IAuthenticationPlugin,
                ILoginPasswordExtractionPlugin,
                ICredentialsUpdatePlugin,
                ICredentialsResetPlugin)

InitializeClass( ASPXAuthPlugin )



