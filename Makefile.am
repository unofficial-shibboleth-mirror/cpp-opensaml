AUTOMAKE_OPTIONS = foreign dist-zip dist-bzip2
ACLOCAL_AMFLAGS = -I m4

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

SUBDIRS = doc schemas saml samlsign

if BUILD_UNITTEST
SUBDIRS += samltest
endif

if DX_COND_doc
all-local: doxygen-doc
else
all-local:
endif

pkgconfig_DATA = @PACKAGE_NAME@.pc

GENFILES = @PACKAGE_NAME@.spec

EXTRA_DIST = $(DX_CONFIG) \
	Projects \
	config_win32.h \
	$(GENFILES) \
	$(GENFILES:%=%.in)
