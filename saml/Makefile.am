AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libsaml.la

libsamlincludedir = $(includedir)/saml

utilincludedir = $(includedir)/saml/util

saml1coreincludedir = $(includedir)/saml/saml1/core

libsamlinclude_HEADERS = \
    base.h \
    exceptions.h \
    version.h \
    SAMLConfig.h

siginclude_HEADERS = \
    signature/SigningContext.h \
    signature/VerifyingContext.h

utilinclude_HEADERS = \
    util/SAMLConstants.h

saml1coreinclude_HEADERS = \
	saml1/core/Assertions.h \
	saml1/core/Protocols.h

noinst_HEADERS = \
    internal.h

libsaml_la_SOURCES = \
    SAMLConfig.cpp \
    saml1/core/impl/AssertionsImpl.cpp \
    saml1/core/impl/AssertionsSchemaValidators.cpp \
    saml1/core/impl/ProtocolsImpl.cpp \
    saml1/core/impl/ProtocolsSchemaValidators.cpp \
    signature/SigningContext.cpp \
    signature/VerifyingContext.cpp \
    util/SAMLConstants.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libsaml_la_LDFLAGS = -version-info 2:0:0

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = saml.vcproj
