AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libsaml.la

libsamlincludedir = $(includedir)/saml

encincludedir = $(includedir)/saml/encryption

secincludedir = $(includedir)/saml/security

sigincludedir = $(includedir)/saml/signature

utilincludedir = $(includedir)/saml/util

samlbindincludedir = $(includedir)/saml/binding

saml1bindincludedir = $(includedir)/saml/saml1/binding

saml1coreincludedir = $(includedir)/saml/saml1/core

saml1profincludedir = $(includedir)/saml/saml1/profile

saml2bindincludedir = $(includedir)/saml/saml2/binding

saml2coreincludedir = $(includedir)/saml/saml2/core

saml2mdincludedir = $(includedir)/saml/saml2/metadata

saml2profincludedir = $(includedir)/saml/saml2/profile

libsamlinclude_HEADERS = \
	Assertion.h \
	base.h \
	exceptions.h \
	version.h \
	RootObject.h \
	SAMLConfig.h

samlbindinclude_HEADERS = \
	binding/ArtifactMap.h \
	binding/MessageDecoder.h \
	binding/MessageEncoder.h \
	binding/SAMLArtifact.h \
	binding/SecurityPolicy.h \
	binding/SecurityPolicyRule.h \
	binding/SOAPClient.h

encinclude_HEADERS = \
	encryption/EncryptedKeyResolver.h

siginclude_HEADERS = \
	signature/ContentReference.h \
	signature/SignableObject.h \
	signature/SignatureProfileValidator.h

utilinclude_HEADERS = \
	util/CommonDomainCookie.h \
	util/SAMLConstants.h

saml1coreinclude_HEADERS = \
	saml1/core/Assertions.h \
	saml1/core/Protocols.h

saml1bindinclude_HEADERS = \
	saml1/binding/SAMLArtifactType0001.h \
	saml1/binding/SAMLArtifactType0002.h \
	saml1/binding/SAML1MessageDecoder.h \
	saml1/binding/SAML1SOAPClient.h

saml1profinclude_HEADERS = \
	saml1/profile/AssertionValidator.h \
	saml1/profile/BrowserSSOProfileValidator.h

saml2coreinclude_HEADERS = \
	saml2/core/Assertions.h \
	saml2/core/Protocols.h

saml2bindinclude_HEADERS = \
	saml2/binding/SAML2Artifact.h \
	saml2/binding/SAML2ArtifactType0004.h \
	saml2/binding/SAML2MessageDecoder.h \
	saml2/binding/SAML2Redirect.h \
	saml2/binding/SAML2SOAPClient.h
	
saml2mdinclude_HEADERS = \
	saml2/metadata/AbstractMetadataProvider.h \
	saml2/metadata/DynamicMetadataProvider.h \
	saml2/metadata/EndpointManager.h \
	saml2/metadata/Metadata.h \
	saml2/metadata/MetadataCredentialContext.h \
	saml2/metadata/MetadataCredentialCriteria.h \
	saml2/metadata/MetadataFilter.h \
	saml2/metadata/MetadataProvider.h \
	saml2/metadata/ObservableMetadataProvider.h

saml2profinclude_HEADERS = \
	saml2/profile/AssertionValidator.h \
	saml2/profile/BrowserSSOProfileValidator.h \
	saml2/profile/SAML2AssertionPolicy.h

noinst_HEADERS = \
	internal.h

libsaml_la_SOURCES = \
	SAMLConfig.cpp \
	binding/impl/ArtifactMap.cpp \
	binding/impl/ClientCertAuthRule.cpp \
	binding/impl/MessageDecoder.cpp \
	binding/impl/MessageEncoder.cpp \
	binding/impl/MessageFlowRule.cpp \
	binding/impl/NullSecurityRule.cpp \
	binding/impl/SAMLArtifact.cpp \
	binding/impl/SecurityPolicy.cpp \
	binding/impl/SimpleSigningRule.cpp \
	binding/impl/SOAPClient.cpp \
	binding/impl/XMLSigningRule.cpp \
	profile/impl/AudienceRestrictionRule.cpp \
    profile/impl/ConditionsRule.cpp \
    profile/impl/IgnoreRule.cpp \
	saml1/core/impl/AssertionsImpl.cpp \
	saml1/core/impl/AssertionsSchemaValidators.cpp \
	saml1/core/impl/ProtocolsImpl.cpp \
	saml1/core/impl/ProtocolsSchemaValidators.cpp \
	saml1/binding/impl/SAMLArtifactType0001.cpp \
	saml1/binding/impl/SAMLArtifactType0002.cpp \
	saml1/binding/impl/SAML1ArtifactDecoder.cpp \
	saml1/binding/impl/SAML1ArtifactEncoder.cpp \
	saml1/binding/impl/SAML1MessageDecoder.cpp \
	saml1/binding/impl/SAML1POSTDecoder.cpp \
	saml1/binding/impl/SAML1POSTEncoder.cpp \
	saml1/binding/impl/SAML1SOAPDecoder.cpp \
	saml1/binding/impl/SAML1SOAPEncoder.cpp \
	saml1/binding/impl/SAML1SOAPClient.cpp \
	saml1/profile/impl/AssertionValidator.cpp \
	saml1/profile/impl/BrowserSSOProfileValidator.cpp \
	saml1/profile/impl/SAML1BrowserSSORule.cpp \
	saml2/core/impl/Assertions.cpp \
	saml2/core/impl/Assertions20Impl.cpp \
	saml2/core/impl/Assertions20SchemaValidators.cpp \
	saml2/core/impl/Protocols20Impl.cpp \
	saml2/core/impl/Protocols20SchemaValidators.cpp \
	saml2/metadata/impl/AbstractMetadataProvider.cpp \
	saml2/metadata/impl/BlacklistMetadataFilter.cpp \
	saml2/metadata/impl/ChainingMetadataProvider.cpp \
	saml2/metadata/impl/DynamicMetadataProvider.cpp \
	saml2/metadata/impl/EntityRoleMetadataFilter.cpp \
	saml2/metadata/impl/MetadataImpl.cpp \
	saml2/metadata/impl/MetadataProvider.cpp \
	saml2/metadata/impl/MetadataSchemaValidators.cpp \
	saml2/metadata/impl/NullMetadataProvider.cpp \
	saml2/metadata/impl/SignatureMetadataFilter.cpp \
	saml2/metadata/impl/RequireValidUntilMetadataFilter.cpp \
	saml2/metadata/impl/WhitelistMetadataFilter.cpp \
	saml2/metadata/impl/XMLMetadataProvider.cpp \
	saml2/binding/impl/SAML2Artifact.cpp \
	saml2/binding/impl/SAML2ArtifactType0004.cpp \
	saml2/binding/impl/SAML2ArtifactDecoder.cpp \
	saml2/binding/impl/SAML2ArtifactEncoder.cpp \
    saml2/binding/impl/SAML2ECPDecoder.cpp \
    saml2/binding/impl/SAML2ECPEncoder.cpp \
    saml2/binding/impl/SAML2MessageDecoder.cpp \
	saml2/binding/impl/SAML2POSTDecoder.cpp \
	saml2/binding/impl/SAML2POSTEncoder.cpp \
	saml2/binding/impl/SAML2Redirect.cpp \
	saml2/binding/impl/SAML2RedirectDecoder.cpp \
	saml2/binding/impl/SAML2RedirectEncoder.cpp \
	saml2/binding/impl/SAML2SOAPDecoder.cpp \
	saml2/binding/impl/SAML2SOAPEncoder.cpp \
	saml2/binding/impl/SAML2SOAPClient.cpp \
	saml2/profile/impl/Assertion20Validator.cpp \
	saml2/profile/impl/BrowserSSOProfile20Validator.cpp \
    saml2/profile/impl/BearerConfirmationRule.cpp \
    saml2/profile/impl/DelegationRestrictionRule.cpp \
	saml2/profile/impl/SAML2AssertionPolicy.cpp \
	encryption/EncryptedKeyResolver.cpp \
	signature/ContentReference.cpp \
	signature/SignatureProfileValidator.cpp \
	util/CommonDomainCookie.cpp \
	util/SAMLConstants.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libsaml_la_LDFLAGS = -version-info 5:0:0

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = saml.vcproj zlib resource.h saml.rc

dist-hook:
	rm -rf `find $(distdir)/zlib -name .svn`
