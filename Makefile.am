AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

dist-hook:
	rm -rf `find $(distdir)/samltest/data -name .svn`
	rm -rf `find $(distdir)/doc/api -name .svn`


SUBDIRS = doc schemas saml samltest samlsign

if DX_COND_doc
all-local: opensaml.spec pkginfo doxygen-doc
else
all-local: opensaml.spec pkginfo
endif

install-data-hook:
	rm -rf $(DESTDIR)$(datadir)/doc/@PACKAGE@/api
	cp -r doc/api $(DESTDIR)$(datadir)/doc/@PACKAGE@

opensaml.spec: opensaml.spec.in Makefile
	rm -f $@.tmp
	sed < $@.in > $@.tmp \
	    -e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@

pkginfo: pkginfo.in Makefile
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
	opensaml.spec.in \
	opensaml.spec \
	pkginfo.in \
	pkginfo \
	depend \
	postinstall

DISTCLEANFILES = opensaml.spec pkginfo
