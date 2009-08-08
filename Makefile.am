AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

dist-hook:
	rm -rf `find $(distdir)/samltest/data -name .svn`
	rm -rf `find $(distdir)/doc/api -name .svn`


SUBDIRS = doc schemas saml samltest samlsign

GENFILES = opensaml.spec pkginfo Portfile

if DX_COND_doc
all-local: doxygen-doc $(GENFILES)
else
all-local: $(GENFILES)
endif

$(GENFILES): %: %.in Makefile
	rm -f $@.tmp
	sed < $@.in > $@.tmp \
	    -e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@

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

DISTCLEANFILES = $(GENFILES)
