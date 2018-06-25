AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = samlsign

samlsign_SOURCES = samlsign.cpp

samlsign_LDADD = $(top_builddir)/saml/libsaml.la
samlsign_CXXFLAGS = \
    $(xmltooling_CFLAGS) \
    $(log4shib_CFLAGS) $(log4cpp_CFLAGS)
samlsign_LDADD += \
    $(xmltooling_LIBS) \
    $(log4shib_LIBS) $(log4cpp_LIBS)

EXTRA_DIST = resource.h samlsign.rc
