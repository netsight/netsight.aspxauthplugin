from plone.app.testing import PloneSandboxLayer
from plone.app.testing import applyProfile
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import IntegrationTesting
from plone.app.testing import FunctionalTesting

from plone.testing import z2

from zope.configuration import xmlconfig


class NetsightaspxauthpluginLayer(PloneSandboxLayer):

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        # Load ZCML
        import netsight.aspxauthplugin
        xmlconfig.file(
            'configure.zcml',
            netsight.aspxauthplugin,
            context=configurationContext
        )

        # Install products that use an old-style initialize() function
        #z2.installProduct(app, 'Products.PloneFormGen')

#    def tearDownZope(self, app):
#        # Uninstall products installed above
#        z2.uninstallProduct(app, 'Products.PloneFormGen')


NETSIGHT_ASPXAUTHPLUGIN_FIXTURE = NetsightaspxauthpluginLayer()
NETSIGHT_ASPXAUTHPLUGIN_INTEGRATION_TESTING = IntegrationTesting(
    bases=(NETSIGHT_ASPXAUTHPLUGIN_FIXTURE,),
    name="NetsightaspxauthpluginLayer:Integration"
)
NETSIGHT_ASPXAUTHPLUGIN_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(NETSIGHT_ASPXAUTHPLUGIN_FIXTURE, z2.ZSERVER_FIXTURE),
    name="NetsightaspxauthpluginLayer:Functional"
)
