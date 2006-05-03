AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

EXTRA_DIST = $(DX_CONFIG) \
	doc \
	schemas \
	cpp-opensaml.sln \
	libtool.m4 \
	doxygen.m4 \
	depcomp \
	config_win32.h \
	opensaml.spec.in \
	opensaml.spec \
	pkginfo.in \
	pkginfo \
	checkinstall


dist-hook:
	rm -rf `find $(distdir)/samltest/data -name .svn`
	rm -rf `find $(distdir)/schemas -name .svn`
	rm -rf `find $(distdir)/schemas -name Makefile`
	rm -rf `find $(distdir)/doc -name .svn`
	rm -rf `find $(distdir)/doc -name Makefile`


SUBDIRS = schemas saml samltest

all-local: opensaml.spec pkginfo doxygen-doc

opensaml.spec: opensaml.spec.in Makefile
	rm -f $@.tmp
	sed < $< > $@.tmp \
	    -e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@

pkginfo: pkginfo.in Makefile
	rm -f $@.tmp
	sed < $< > $@.tmp \
	    -e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@

DISTCLEANFILES = opensaml.spec pkginfo
