AC_PREREQ([2.50])
AC_INIT([opensaml],[3.2.0],[https://issues.shibboleth.net/],[opensaml])
AC_CONFIG_SRCDIR(saml)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
PKG_INSTALLDIR

# Doxygen features
DX_HTML_FEATURE(ON)
DX_DOT_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(opensaml, doxygen.cfg, doc/api)

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Produce debug variant (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    AM_CFLAGS="-D_DEBUG"
    AM_CXXFLAGS="-D_DEBUG"
fi

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([opensaml.pc opensaml.spec])
AC_CONFIG_FILES([Makefile saml/Makefile samltest/Makefile samlsign/Makefile schemas/Makefile doc/Makefile])

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])

if test "$GCC" = "yes" ; then
    AM_CFLAGS="$AM_CFLAGS -Wall -W"
    AM_CXXFLAGS="$AM_CXXFLAGS -Wall -W"
fi

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])

LT_INIT([disable-static])

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

AX_PKG_CHECK_MODULES([xerces],,[xerces-c >= 3.2])

AX_PKG_CHECK_MODULES([xmlsec],,[xml-security-c >= 2])

AX_PKG_CHECK_MODULES([xmltooling],,[xmltooling >= 3.1])
PKG_CHECK_VAR([DX_INCLUDE], [xmltooling], [includedir])

# Check for unit test support
AC_ARG_VAR([CXXTEST], [override the cxxtestgen executable and options])
AC_CHECK_PROGS([CXXTEST], [cxxtestgen cxxtestgen.pl], [false])
AC_ARG_VAR([CXXTESTFLAGS], [override the cxxtest compiler flags needed to build tests])
AM_CONDITIONAL([BUILD_UNITTEST], [test "x${CXXTEST}" != xfalse])

AC_ARG_WITH([pkgxmldir],
    AS_HELP_STRING([--with-pkgxmldir],
        [where to install the schema files @<:@default=${datadir}/xml/AC_PACKAGE_TARNAME@:>@])],
    [],[with_pkgxmldir=${datadir}/xml/AC_PACKAGE_TARNAME])
AC_SUBST([pkgxmldir],[${with_pkgxmldir}])

# output packaging and makefiles
AC_OUTPUT
