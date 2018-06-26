AUTOMAKE_OPTIONS = foreign subdir-objects

TESTS = samltest

check_PROGRAMS = samltest

samltest_h = \
    SAMLArtifactCreationTest.h \
    SAMLArtifactType0001Test.h \
    SAMLArtifactType0002Test.h \
    SAMLArtifactType0004Test.h \
    ArtifactMapTest.h \
    CookieTest.h \
    encryption/EncryptedAssertionTest.h \
    signature/SAML1AssertionTest.h \
    signature/SAML1RequestTest.h \
    signature/SAML1ResponseTest.h \
    signature/SAML2AssertionTest.h \
    security/ExplicitKeyTrustEngineTest.h \
    security/StaticPKIXTrustEngineTest.h \
    saml1/core/impl/ActionTest.h \
    saml1/core/impl/AdviceTest.h \
    saml1/core/impl/AssertionIDReferenceTest.h \
    saml1/core/impl/AssertionTest.h \
    saml1/core/impl/AttributeDesignatorTest.h \
    saml1/core/impl/AttributeStatementTest.h \
    saml1/core/impl/AttributeTest.h \
    saml1/core/impl/AudienceRestrictionConditionTest.h \
    saml1/core/impl/AudienceTest.h \
    saml1/core/impl/AuthenticationStatementTest.h \
    saml1/binding/SAML1ArtifactTest.h \
    saml1/binding/SAML1POSTTest.h \
    saml1/profile/SAML1PolicyTest.h \
    saml2/core/impl/Action20Test.h \
    saml2/core/impl/Advice20Test.h \
    saml2/core/impl/Artifact20Test.h \
    saml2/core/impl/ArtifactResolve20Test.h \
    saml2/core/impl/ArtifactResponse20Test.h \
    saml2/core/impl/Assertion20Test.h \
    saml2/core/impl/AssertionIDRef20Test.h \
    saml2/core/impl/AssertionIDRequest20Test.h \
    saml2/core/impl/AssertionURIRef20Test.h \
    saml2/core/impl/Attribute20Test.h \
    saml2/core/impl/AttributeQuery20Test.h \
    saml2/core/impl/AttributeStatement20Test.h \
    saml2/core/impl/Audience20Test.h \
    saml2/core/impl/AudienceRestriction20Test.h \
    saml2/core/impl/AuthenticatingAuthority20Test.h \
    saml2/core/impl/AuthnContext20Test.h \
    saml2/core/impl/AuthnContextClassRef20Test.h \
    saml2/core/impl/AuthnContextDeclRef20Test.h \
    saml2/core/impl/AuthnQuery20Test.h \
    saml2/core/impl/AuthnRequest20Test.h \
    saml2/core/impl/AuthnStatement20Test.h \
    saml2/core/impl/AuthzDecisionQuery20Test.h \
    saml2/core/impl/AuthzDecisionStatement20Test.h \
    saml2/core/impl/Conditions20Test.h \
    saml2/core/impl/Evidence20Test.h \
    saml2/core/impl/GetComplete20Test.h \
    saml2/core/impl/IDPEntry20Test.h \
    saml2/core/impl/IDPList20Test.h \
    saml2/core/impl/Issuer20Test.h \
    saml2/core/impl/KeyInfoConfirmationDataType20Test.h\
    saml2/core/impl/LogoutRequest20Test.h \
    saml2/core/impl/LogoutResponse20Test.h \
    saml2/core/impl/ManageNameIDRequest20Test.h \
    saml2/core/impl/ManageNameIDResponse20Test.h \
    saml2/core/impl/NameIDMappingRequest20Test.h \
    saml2/core/impl/NameIDMappingResponse20Test.h \
    saml2/core/impl/NameIDPolicy20Test.h \
    saml2/core/impl/NameID20Test.h \
    saml2/core/impl/NameIDType20Test.h \
    saml2/core/impl/NewEncryptedID20Test.h \
    saml2/core/impl/NewID20Test.h \
    saml2/core/impl/OneTimeUse20Test.h \
    saml2/core/impl/ProxyRestriction20Test.h \
    saml2/core/impl/RequesterID20Test.h \
    saml2/core/impl/RequestedAuthnContext20Test.h \
    saml2/core/impl/Response20Test.h \
    saml2/core/impl/Scoping20Test.h \
    saml2/core/impl/SessionIndex20Test.h \
    saml2/core/impl/Status20Test.h \
    saml2/core/impl/StatusCode20Test.h \
    saml2/core/impl/StatusDetail20Test.h \
    saml2/core/impl/StatusMessage20Test.h \
    saml2/core/impl/Subject20Test.h\
    saml2/core/impl/SubjectConfirmation20Test.h\
    saml2/core/impl/SubjectConfirmationData20Test.h\
    saml2/core/impl/SubjectLocality20Test.h\
    saml2/core/impl/Terminate20Test.h \
    saml2/binding/SAML2ArtifactTest.h \
    saml2/binding/SAML2POSTTest.h \
    saml2/binding/SAML2RedirectTest.h \
    saml2/metadata/XMLMetadataProviderTest.h \
    saml2/profile/SAML2PolicyTest.h

noinst_HEADERS = \
    binding.h \
    internal.h \
    signature/SAMLSignatureTestBase.h \
    samltest.h \
    $(samltest_h)

nodist_samltest_SOURCES = $(samltest_h:.h=.cpp) samltest.cpp

CLEANFILES = $(nodist_samltest_SOURCES)

samltest.cpp: samltest.h
	$(CXXTEST) --have-eh --have-std --abort-on-fail --error-printer -o $@ $<

$(samltest_h:.h=.cpp): %.cpp: %.h
	$(CXXTEST) --have-eh --have-std --abort-on-fail --part -o $@ $<

samltest_CXXFLAGS = \
    $(CXXTESTFLAGS) \
    $(xerces_CFLAGS) \
    $(xmlsec_CFLAGS) \
    $(xmltooling_CFLAGS)
samltest_LDADD = $(top_builddir)/saml/libsaml.la \
    $(xerces_LIBS) \
    $(xmlsec_LIBS) \
    $(xmltooling_LIBS)

EXTRA_DIST = data
