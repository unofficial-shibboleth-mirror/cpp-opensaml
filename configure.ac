AC_PREREQ([2.50])
AC_INIT([opensaml],[3.0.0],[https://issues.shibboleth.net/],[opensaml])
AC_CONFIG_SRCDIR(saml)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

# Docygen features
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(opensaml, doxygen.cfg, doc/api)

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Have GCC compile with symbols (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -Wall -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -Wall -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -Wall -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -Wall -O2 -DNDEBUG"
fi

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([opensaml.pc opensaml.spec])
AC_CONFIG_FILES([Makefile saml/Makefile samltest/Makefile samlsign/Makefile schemas/Makefile doc/Makefile])

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])
AC_CANONICAL_HOST

if test "$GCC" = "yes" ; then
#    AC_HAVE_GCC_VERSION(4,0,0,0,
#        [
#        AC_DEFINE(GCC_HASCLASSVISIBILITY,1,
#            [Define to enable class visibility control in gcc.])
#        GCC_CFLAGS="$GCC_CFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
#        GCC_CXXFLAGS="$GCC_CXXFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
#        ])
    CFLAGS="$GCC_CFLAGS"
    CXXFLAGS="$GCC_CXXFLAGS"
fi

# Fix for Sun Workshop compiler in debug mode, may be Sun case #6360993
# Also enables POSIX semantics for some functions.
case "${host_cpu}-${host_os}" in
    *solaris*)
	CFLAGS="$CFLAGS -D_POSIX_PTHREAD_SEMANTICS"
	CXXFLAGS="$CXXFLAGS -D_POSIX_PTHREAD_SEMANTICS"
	if test "$CXX" = "CC" ; then
		CXXFLAGS="$CXXFLAGS -Qoption ccfe -stabs=no%dfltlit+no%dflthlp"
	fi
    ;;
esac

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_DIRENT

# Checks for library functions.
AC_CHECK_FUNCS([strchr strdup strstr])

AX_PTHREAD(,[AC_MSG_ERROR([unable to find pthreads, currently this is required])])

AC_LANG([C++])

# C++ requirements
AC_CXX_NAMESPACES
AC_CXX_REQUIRE_STL

# Boost
BOOST_REQUIRE
BOOST_BIND
BOOST_LAMBDA
BOOST_POINTER_CONTAINER
BOOST_SMART_PTR
BOOST_STRING_ALGO

AX_PKG_CHECK_MODULES([log4shib],,[log4shib],
    [AC_DEFINE([OPENSAML_LOG4SHIB],[1],[Define to 1 if log4shib library is used.])],
    [AX_PKG_CHECK_MODULES([log4cpp],,[log4cpp],
        [AC_DEFINE([OPENSAML_LOG4CPP],[1],[Define to 1 if log4cpp library is used.])])])

# Xerces-C v2.6.0 has bugs that inhibit use with signed XML
AX_PKG_CHECK_MODULES([xerces],,[xerces-c != 3.0])

AX_PKG_CHECK_MODULES([xmlsec],,[xml-security-c >= 2])

AX_PKG_CHECK_MODULES([xmltooling],,[xmltooling >= 3])
PKG_CHECK_VAR([DX_INCLUDE], [xmltooling], [includedir])

# Check for unit test support
CXXTEST="/usr/bin/cxxtestgen.pl"
CXXTESTFLAGS=""
AC_ARG_WITH(cxxtest,
    AS_HELP_STRING([--with-cxxtest=PATH], [where cxxtest is installed]),
    [if test x_$with_cxxtest != x_/usr; then
        CXXTEST="${with_cxxtest}/cxxtestgen.pl"
        CXXTESTFLAGS="-I${with_cxxtest}"
    fi])
if ! test -f "${CXXTEST}"; then
    AC_MSG_WARN([cxxtestgen not found, won't build unit tests])
fi

AC_SUBST(CXXTEST)
AC_SUBST(CXXTESTFLAGS)
AM_CONDITIONAL(BUILD_UNITTEST,test -f ${CXXTEST})

# output packaging and makefiles
AC_OUTPUT
