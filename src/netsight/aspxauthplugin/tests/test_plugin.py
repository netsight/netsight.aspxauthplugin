import unittest2 as unittest
import time
from cStringIO import StringIO

from zope.component import testing
from Testing import ZopeTestCase
from Products.Five import zcml

from netsight.aspxauthplugin.plugin import ASPXAuthPlugin, ReadFormsAuthTicketString, WriteFormsAuthTicketString
import netsight.aspxauthplugin

#from netsight.aspxauthplugin.testing import \
#    NETSIGHT_ASPXAUTHPLUGIN_INTEGRATION_TESTING

SANDBOX_ID = 'sandbox'

class PASLayer:
    @classmethod
    def setUp( cls ):
        testing.setUp()

        app = ZopeTestCase.app()

        # Create our sandbox
        app.manage_addFolder(SANDBOX_ID)
        sandbox = app[SANDBOX_ID]

        factory = sandbox.manage_addProduct['PluggableAuthService']
        factory.addPluggableAuthService(REQUEST=None)
        
        pas = sandbox.acl_users
        netsight.aspxauthplugin.install.manage_add_aspxauthplugin(pas, 'aspxauth')

        # need to monkey patch in a response object into the right place
        pas.aspxauth.REQUEST.RESPONSE = pas.aspxauth.REQUEST.response
        cls.pas = pas

    @classmethod
    def tearDown(cls):
        testing.tearDown()
        app = ZopeTestCase.app()
#        app.manage_delObjects(SANDBOX_ID)
#        transaction.commit()
        ZopeTestCase.close(app)

class TestASPXAuth(ZopeTestCase.ZopeTestCase):

    layer = PASLayer

    def setUp(self):
        # you'll want to use this to set up anything you need for your tests
        # below
        pass

    def test_ReadFormsAuthTicketString(self):
        data = '\x01/\x00'
        f = StringIO(data)
        self.assertEqual(ReadFormsAuthTicketString(f), '/')

    def test_ReadFormsAuthTicketStringEmpty(self):
        data = '\x00'
        f = StringIO(data)
        self.assertEqual(ReadFormsAuthTicketString(f), '')

    def test_WriteFormsAuthTicketString(self):
        data = '\x01/\x00'
        f = StringIO()
        WriteFormsAuthTicketString(f, '/')
        f.seek(0)
        self.assertEqual(f.read(), data)

    def test_WriteFormsAuthTicketStringEmpty(self):
        data = '\x00'
        f = StringIO()
        WriteFormsAuthTicketString(f, '')
        f.seek(0)
        self.assertEqual(f.read(), data)

    def test_unpack_data(self):
        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """C50B3C89CB21F4F1422FF158A5B42D0E8DB8CB5CDA1742572A487D9401E3400267682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE"""
        plugin.decryption_key = """8A9BE8FD67AF6979E7D20198CFEA50DD3D3799C77AF2B72F"""

        cookie = """75DC73A5006682E1436110A45FFD840D8F6DD9807A132D0AEB1281C229D37502EDD60D518C9FECB73E3869F457BB43230566F26716DEB27FC98AE76A0318C64077D191D2FD5CCB87982648E7050BB049A622D25857D87B84DFFF6492941A9C07CE8118A714D9587E7B436500A93B8788C1979AC989DF0471A1A60D22EA903FF1A5E27956DC678E57C7CE299893D9BFFB7651AA9BB97E7BED9B0511EE6F79906B09F2BB84"""

        sig,data = plugin.decodeCookie(cookie)
        foo = plugin.decryptData(data)
        self.assertEqual(plugin.unpackData(foo), (1372332733, 1372336333, u'aafc752c-8247-4f44-938c-a1ea00be2070', 2, 0, '', u'/'))


    def test_repack_cookie(self):
        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """07B6387D1DED6BF193EDD726B4ADFD6B92EDA470DDF639D4B78110CA797DCED426BECF322B9FBCC5E7C3FDA2E7BA28169611B1ACD1E7F063ABF17ECDC30AD482"""
        plugin.decryption_key = """CFE45C8F9D17D68B71DAB98158E1F78E5AC05D6C5A7184BD1BF26E6E36FA5973"""

        start_time = int(time.time())
        end_time = int(start_time + (60 * 20) )
        username = 'matth@netsight.co.uk'
        version = 2
        persistent = None
        userdata = None
        path = None

        data = plugin.packData(start_time, end_time, username, version, persistent, userdata, path)
        values = plugin.unpackData(data)

        self.assertEqual(values, (start_time, end_time, username, version, 0, '', '/'))


    def test_rebuild_cookie(self):
        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """07B6387D1DED6BF193EDD726B4ADFD6B92EDA470DDF639D4B78110CA797DCED426BECF322B9FBCC5E7C3FDA2E7BA28169611B1ACD1E7F063ABF17ECDC30AD482"""
        plugin.decryption_key = """CFE45C8F9D17D68B71DAB98158E1F78E5AC05D6C5A7184BD1BF26E6E36FA5973"""

        start_time = int(time.time())
        end_time = int(start_time + (60 * 20) )
        username = 'matth@netsight.co.uk'
        version = 2
        persistent = None
        userdata = None
        path = None

        cookie = plugin.encryptCookie(start_time, end_time, username, version, persistent, userdata, path)
        sig, data = plugin.decodeCookie(cookie)
        data = plugin.decryptData(data)

        self.assertEqual(plugin.unpackData(data), (start_time, end_time, username, version, 0, '', '/'))


    def test_auth_pass1(self):
        from netsight.aspxauthplugin import plugin
        def mytime():
            return 1372414992
        plugin.time_time = mytime

        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """07B6387D1DED6BF193EDD726B4ADFD6B92EDA470DDF639D4B78110CA797DCED426BECF322B9FBCC5E7C3FDA2E7BA28169611B1ACD1E7F063ABF17ECDC30AD482"""
        plugin.decryption_key = """CFE45C8F9D17D68B71DAB98158E1F78E5AC05D6C5A7184BD1BF26E6E36FA5973"""

        cookie = """15DA8E39EE8AEED1B9D8BF88509A86249716B6C9196A79E7DE28EF7355700AA0E4F438FD0021349A7DB86B326463C7B427E6F107A604AE24E5817251E4F7763A4318E3DB77FD124A24DADC5A89CDB914D31A1BC6A8355A60AB3028E035DE6DFEB98E095B67FA377FA80BBF96E05039AC2F2D1A536C1669DD41DEDA60938CD0797C10824B56F197F4C6DBE2C9F9CDCE298B835027"""
        self.assertEqual(plugin.authenticateCredentials({'cookie': cookie, 'plugin': plugin.getId()}), ('matth@netsight.co.uk', 'matth@netsight.co.uk'))

    def test_auth_pass2(self):
        from netsight.aspxauthplugin import plugin
        def mytime():
            return 1372332734
        plugin.time_time = mytime

        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """C50B3C89CB21F4F1422FF158A5B42D0E8DB8CB5CDA1742572A487D9401E3400267682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE"""
        plugin.decryption_key = """8A9BE8FD67AF6979E7D20198CFEA50DD3D3799C77AF2B72F"""

        cookie = """75DC73A5006682E1436110A45FFD840D8F6DD9807A132D0AEB1281C229D37502EDD60D518C9FECB73E3869F457BB43230566F26716DEB27FC98AE76A0318C64077D191D2FD5CCB87982648E7050BB049A622D25857D87B84DFFF6492941A9C07CE8118A714D9587E7B436500A93B8788C1979AC989DF0471A1A60D22EA903FF1A5E27956DC678E57C7CE299893D9BFFB7651AA9BB97E7BED9B0511EE6F79906B09F2BB84"""
        self.assertEqual(plugin.authenticateCredentials({'cookie': cookie, 'plugin': plugin.getId()}), ('aafc752c-8247-4f44-938c-a1ea00be2070', 'aafc752c-8247-4f44-938c-a1ea00be2070'))


    def test_auth_pass2_expiredcookie(self):
        from netsight.aspxauthplugin import plugin
        def mytime():
            return 1372336334
        plugin.time_time = mytime

        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """C50B3C89CB21F4F1422FF158A5B42D0E8DB8CB5CDA1742572A487D9401E3400267682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE"""
        plugin.decryption_key = """8A9BE8FD67AF6979E7D20198CFEA50DD3D3799C77AF2B72F"""

        cookie = """75DC73A5006682E1436110A45FFD840D8F6DD9807A132D0AEB1281C229D37502EDD60D518C9FECB73E3869F457BB43230566F26716DEB27FC98AE76A0318C64077D191D2FD5CCB87982648E7050BB049A622D25857D87B84DFFF6492941A9C07CE8118A714D9587E7B436500A93B8788C1979AC989DF0471A1A60D22EA903FF1A5E27956DC678E57C7CE299893D9BFFB7651AA9BB97E7BED9B0511EE6F79906B09F2BB84"""
        self.assertEqual(plugin.authenticateCredentials({'cookie': cookie, 'plugin': plugin.getId()}), None)

    def test_auth_fail_badcookie(self):
        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """07B6387D1DED6BF193EDD726B4ADFD6B92EDA470DDF639D4B78110CA797DCED426BECF322B9FBCC5E7C3FDA2E7BA28169611B1ACD1E7F063ABF17ECDC30AD482"""
        plugin.decryption_key = """CFE45C8F9D17D68B71DAB98158E1F78E5AC05D6C5A7184BD1BF26E6E36FA5973"""

        cookie = """31EBBD78D6F27972394A513A161AD0362E7906830460CE7D3F44E47B2F1AF63DD43E02EB22259E4AF342B232768D6701C9395AF42448E5D149FE8AE2E4D355E9F43A9B60E1A30C0282F9ED470D8037F3B9D1D965293BED7C6156672527A94B22F24039C3F7CA6ECFF6D50A0BFFB38C0E03FF9644092FB5F8FD6E6292AA7A49B5FF603456DE4EA041F785CC163A92C34937FDE018""" 

        self.assertEqual(plugin.authenticateCredentials({'cookie': cookie, 'plugin': plugin.getId()}), None)

    def test_crypto_fail_validation_key(self):
        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """07B6387D1DED6BF193EDD726B4ADFD6B92EDA470DDF639D4B78110CA797DCED426BECF322B9FBCC5E7C3FDA2E7BA28169611B1ACD1E7F063ABF17ECDC30AD483"""
        plugin.decryption_key = """CFE45C8F9D17D68B71DAB98158E1F78E5AC05D6C5A7184BD1BF26E6E36FA5973"""

        cookie = """31EBBD78D6F27972394A513A161AD0362E7906830460CE7D3F44E47B2F1AF63DD43E02EB22259E4AF342B232768D6701C9395AF42448E5D149FE8AE2E4D355E9F43A9B60E1A30C0282F9ED470D8037F3B9D1D965293BED7C6156672527A94B22F24039C3F7CA6ECFF6D50A0BFFB38C0E03FF9644092FB5F8FD6E6292AA7A49B5FF603456DE4EA041F785CC163A92C34937FDE017""" 

        self.assertEqual(plugin.authenticateCredentials({'cookie': cookie, 'plugin': plugin.getId()}), None)

    def test_crypto_fail_decryption_key(self):
        plugin = self.layer.pas.aspxauth
        plugin.validation_key = """07B6387D1DED6BF193EDD726B4ADFD6B92EDA470DDF639D4B78110CA797DCED426BECF322B9FBCC5E7C3FDA2E7BA28169611B1ACD1E7F063ABF17ECDC30AD482"""
        plugin.decryption_key = """CFE45C8F9D17D68B71DAB98158E1F78E5AC05D6C5A7184BD1BF26E6E36FA5972"""

        cookie = """31EBBD78D6F27972394A513A161AD0362E7906830460CE7D3F44E47B2F1AF63DD43E02EB22259E4AF342B232768D6701C9395AF42448E5D149FE8AE2E4D355E9F43A9B60E1A30C0282F9ED470D8037F3B9D1D965293BED7C6156672527A94B22F24039C3F7CA6ECFF6D50A0BFFB38C0E03FF9644092FB5F8FD6E6292AA7A49B5FF603456DE4EA041F785CC163A92C34937FDE017""" 

        self.assertEqual(plugin.authenticateCredentials({'cookie': cookie, 'plugin': plugin.getId()}), None)
