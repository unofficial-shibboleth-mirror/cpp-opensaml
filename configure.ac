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

# checks for pthreads
ACX_PTHREAD(
    [AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.])],
    [AC_MSG_ERROR([unable to find pthreads, currently this is required])])


# OpenSSL settings
AC_ARG_WITH(openssl,
    AS_HELP_STRING([--with-openssl=PATH],[where openssl is installed]),
    [if test x_$with_openssl != x_/usr; then
        SSLFLAGS="-I${with_openssl}/include"
        SSLLIBS="-L${with_openssl}/lib -lcrypto -lssl"
    else
        SSLLIBS="-lcrypto -lssl"
    fi])

if test "x$with_openssl" = "x" ; then
    AC_PATH_PROG(PKG_CONFIG, pkg-config)
    if test "x$PKG_CONFIG" != x && test "x$PKG_CONFIG" != "xno" ; then
        if pkg-config openssl ; then
            SSLLIBS="`$PKG_CONFIG --libs openssl`"
            SSLFLAGS="`$PKG_CONFIG --cflags openssl`"
        else
            AC_MSG_WARN([OpenSSL not supported by pkg-config, try --with-openssl instead])
        fi
    fi
fi

if test "x$SSLLIBS" = "x" ; then
    SSLLIBS="-lcrypto -lssl"
fi

AC_MSG_CHECKING(for OpenSSL cflags)
AC_MSG_RESULT($SSLFLAGS)
CPPFLAGS="$SSLFLAGS $CPPFLAGS"
AC_MSG_CHECKING(for OpenSSL libraries)
AC_MSG_RESULT($SSLLIBS)
LIBS="$LIBS $SSLLIBS"

AC_CHECK_HEADER([openssl/x509.h],,AC_MSG_ERROR([unable to find openssl header files]))

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

# Xerces settings
AC_ARG_WITH(xerces,
    AS_HELP_STRING([--with-xerces=PATH],[where xerces-c is installed]),,
    [with_xerces=/usr])
if test x_$with_xerces != x_/usr; then
    CPPFLAGS="-I${with_xerces}/include $CPPFLAGS"
    LIBS="-L${with_xerces}/lib -lxerces-c $LIBS"
else
    LIBS="-lxerces-c $LIBS"
fi

AC_CHECK_HEADER([xercesc/dom/DOM.hpp],,AC_MSG_ERROR([unable to find xerces header files]))
AC_MSG_CHECKING([Xerces version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xercesc/util/XercesVersion.hpp>],
[#if  _XERCES_VERSION >= 30000
int i = 0;
#else
#error cannot use version 1.x or 2.x
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([Xerces-C 3.x is required])])

AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <xercesc/util/PlatformUtils.hpp>]],[[xercesc::XMLPlatformUtils::Initialize()]])],
    ,[AC_MSG_ERROR([unable to link with Xerces])])

# XML-Security settings
AC_ARG_WITH(xmlsec,
    AS_HELP_STRING([--with-xmlsec=PATH],[where xmlsec is installed]),,
    [with_xmlsec=/usr])
if test x_$with_xmlsec != x_/usr; then
    CPPFLAGS="-I${with_xmlsec}/include $CPPFLAGS"
    LIBS="-L${with_xmlsec}/lib -lxml-security-c $LIBS"
else
    LIBS="-lxml-security-c $LIBS"
fi
AC_CHECK_HEADER([xsec/utils/XSECPlatformUtils.hpp],,AC_MSG_ERROR([unable to find xmlsec header files]))
AC_MSG_CHECKING([XML-Security version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xsec/utils/XSECPlatformUtils.hpp>],
    [#if XSEC_VERSION_MAJOR >= 2
int i = 0;
#else
#error need version 2.0.0 or later
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([XML-Security version 2.0.0 or greater is required.])])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <xsec/utils/XSECPlatformUtils.hpp>]],
        [[XSECPlatformUtils::Initialise()]])],,
    [AC_MSG_ERROR([unable to link with XML-Security])])

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
