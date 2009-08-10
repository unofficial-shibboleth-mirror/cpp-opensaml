AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

dist-hook:
	rm -rf `find $(distdir)/samltest/data -name .svn`
	rm -rf `find $(distdir)/doc/api -name .svn`


SUBDIRS = doc schemas saml samltest samlsign

if DX_COND_doc
all-local: doxygen-doc
else
all-local:
endif

GENFILES = opensaml.spec pkginfo Portfile

EXTRA_DIST = $(DX_CONFIG) \
	cpp-opensaml2.sln \
	libtool.m4 \
	doxygen.m4 \
	acx_pthread.m4 \
	depcomp \
	config_win32.h \
	$(GENFILES) \
	$(GENFILES:%=%.in) \
	depend \
	postinstall
