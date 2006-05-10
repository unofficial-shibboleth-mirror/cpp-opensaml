AUTOMAKE_OPTIONS = foreign

if BUILD_UNITTEST
bin_PROGRAMS = samltest
samltest_CXXFLAGS = $(CXXFLAGS) $(CXXTESTFLAGS)
else
bin_PROGRAMS = 
endif

samltest_h = \
    samltest.h \
    saml1/core/impl/ActionTest.h

noinst_HEADERS = \
    internal.h

nodist_samltest_SOURCES = $(samltest_h:.h=.cpp)

CLEANFILES = $(nodist_samltest_SOURCES)

do-cxxtestgen:
	if test $(HFILE) = "samltest.h"; then \
		$(CXXTEST) --error-printer --have-eh --have-std --abort-on-fail -o $(CPPFILE) $(HFILE); \
	else \
		$(CXXTEST) --part --have-eh --have-std --abort-on-fail -o $(CPPFILE) $(HFILE); \
	fi;

$(nodist_samltest_SOURCES): %.cpp: %.h
	$(MAKE) do-cxxtestgen HFILE=$< CPPFILE=$@

samltest_LDADD = $(top_builddir)/saml/libsaml.la

EXTRA_DIST = samltest.vcproj $(samltest_h) data
