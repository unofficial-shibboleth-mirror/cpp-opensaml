AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libsaml.la

libsamlincludedir = $(includedir)/saml

encincludedir = $(includedir)/saml/encryption

secincludedir = $(includedir)/saml/security

sigincludedir = $(includedir)/saml/signature

utilincludedir = $(includedir)/saml/util

saml1coreincludedir = $(includedir)/saml/saml1/core

saml2coreincludedir = $(includedir)/saml/saml2/core

saml2mdincludedir = $(includedir)/saml/saml2/metadata

libsamlinclude_HEADERS = \
	base.h \
	exceptions.h \
	version.h \
	SAMLConfig.h

samlbindinclude_HEADERS = \
	SAMLArtifact.h

encinclude_HEADERS = \
	encryption/EncryptedKeyResolver.h

secinclude_HEADERS = \
	security/AbstractPKIXTrustEngine.h \
	security/MetadataKeyInfoIterator.h \
	security/ChainingTrustEngine.h \
	security/TrustEngine.h \
	security/X509TrustEngine.h

siginclude_HEADERS = \
	signature/ContentReference.h \
	signature/SignableObject.h \
	signature/SignatureProfileValidator.h

utilinclude_HEADERS = \
	util/SAMLConstants.h

saml1coreinclude_HEADERS = \
	saml1/core/Assertions.h \
	saml1/core/Protocols.h

saml1bindinclude_HEADERS = \
	saml1/core/SAMLArtifactType0001.h \
	saml1/core/SAMLArtifactType0002.h

saml2coreinclude_HEADERS = \
	saml2/core/Assertions.h \
	saml2/core/Protocols.h

saml2bindinclude_HEADERS = \
	saml2/core/SAML2Artifact.h \ 
	saml2/core/SAML2ArtifactType0004.h

saml2mdinclude_HEADERS = \
	saml2/metadata/AbstractMetadataProvider.h \
	saml2/metadata/ChainingMetadataProvider.h \
	saml2/metadata/Metadata.h \
	saml2/metadata/MetadataFilter.h \
	saml2/metadata/MetadataProvider.h \
	saml2/metadata/ObservableMetadataProvider.h

noinst_HEADERS = \
	internal.h

libsaml_la_SOURCES = \
	SAMLConfig.cpp \
	binding/SAMLArtifact.cpp \
	saml1/core/impl/AssertionsImpl.cpp \
	saml1/core/impl/AssertionsSchemaValidators.cpp \
	saml1/core/impl/ProtocolsImpl.cpp \
	saml1/core/impl/ProtocolsSchemaValidators.cpp \
	saml1/binding/impl/SAMLArtifactType0001.cpp \
	saml1/binding/impl/SAMLArtifactType0002.cpp \
	saml2/core/impl/Assertions20Impl.cpp \
	saml2/core/impl/Assertions20SchemaValidators.cpp \
	saml2/core/impl/Protocols20Impl.cpp \
	saml2/core/impl/Protocols20SchemaValidators.cpp \
	saml2/metadata/impl/AbstractMetadataProvider.cpp \
	saml2/metadata/impl/BlacklistMetadataFilter.cpp \
	saml2/metadata/impl/ChainingMetadataProvider.cpp \
	saml2/metadata/impl/FilesystemMetadataProvider.cpp \
	saml2/metadata/impl/MetadataImpl.cpp \
	saml2/metadata/impl/MetadataProvider.cpp \
	saml2/metadata/impl/MetadataSchemaValidators.cpp \
	saml2/metadata/impl/ObservableMetadataProvider.cpp \
	saml2/metadata/impl/SignatureMetadataFilter.cpp \
	saml2/metadata/impl/WhitelistMetadataFilter.cpp \
	saml2/binding/impl/SAML2Artifact.cpp \
	saml2/binding/impl/SAML2ArtifactType0004.cpp \
	encryption/EncryptedKeyResolver.cpp \
	security/impl/TrustEngine.cpp \
	security/impl/AbstractPKIXTrustEngine.cpp \
	security/impl/ChainingTrustEngine.cpp \
	security/impl/ExplicitKeyTrustEngine.cpp \
	signature/ContentReference.cpp \
	signature/SignatureProfileValidator.cpp \
	util/SAMLConstants.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libsaml_la_LDFLAGS = -version-info 2:0:0

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = saml.vcproj
