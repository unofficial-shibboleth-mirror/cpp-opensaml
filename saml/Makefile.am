AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libsaml.la

libsamlincludedir = $(includedir)/saml

sigincludedir = $(includedir)/saml/signature

utilincludedir = $(includedir)/saml/util

libsamlinclude_HEADERS = \
    base.h \
    exceptions.h \
    version.h \
    SAMLConfig.h

utilinclude_HEADERS = \
    util/XMLConstants.h

noinst_HEADERS = \
    internal.h

libsaml_la_SOURCES = \
    SAMLConfig.cpp \
    util/XMLConstants.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libxmltooling_la_LDFLAGS = -version-info 2:0:0

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = saml.vcproj
