AUTOMAKE_OPTIONS = foreign

pkgdocdir = $(datadir)/doc/@PACKAGE@-@PACKAGE_VERSION@

install-data-hook:
	if test -d api ; then \
		cp -r api $(DESTDIR)$(pkgdocdir); \
		rm -rf `find $(DESTDIR)$(pkgdocdir)/api -name .svn`; \
	fi;

docfiles = \
	README.txt \
	LICENSE.txt \
	NOTICE.txt \
	LOG4CPP.LICENSE

pkgdoc_DATA = $(docfiles)

EXTRA_DIST = $(docfiles) api
