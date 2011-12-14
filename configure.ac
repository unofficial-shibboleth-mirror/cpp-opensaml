AC_PREREQ([2.50])
AC_INIT([opensaml],[2.5],[https://issues.shibboleth.net/],[opensaml])
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
DX_INCLUDE=

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
AC_CONFIG_FILES([opensaml.spec])
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
AC_CHECK_SIZEOF(time_t)

# checks for pthreads
ACX_PTHREAD([enable_threads="pthread"],[enable_threads="no"])
if test $enable_threads != "pthread"; then
    AC_MSG_ERROR([unable to find pthreads, currently this is required])
else
    AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.])
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
    CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS"
fi

# zlib settings
AC_ARG_WITH(zlib,
    AS_HELP_STRING([--with-zlib=PATH],[where zlib is installed]),
    [
        if test -d "$withval" ; then
            CPPFLAGS="${CPPFLAGS} -I$withval/include"
            LDFLAGS="${LDFLAGS} -L$withval/lib"
        fi
    ]
)

AC_ARG_WITH(zlib,
    AS_HELP_STRING([--with-zlib=PATH],[where zlib is installed]),,
    [with_zlib=/usr])
if test x_$with_zlib != x_/usr; then
    CPPFLAGS="-I${with_zlib}/include $CPPFLAGS"
    LIBS="-L${with_zlib}/lib -lz $LIBS"
else
    LIBS="-lz $LIBS"
fi

AC_CHECK_HEADER([zlib.h],,AC_MSG_ERROR([unable to find zlib header files]))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <zlib.h>]],
        [[zlibVersion()]])],,
    [AC_MSG_ERROR([unable to link with zlib])])


# OpenSSL settings
AC_ARG_WITH(openssl,
    AS_HELP_STRING([--with-openssl=PATH],[where openssl is installed]),
    [if test x_$with_openssl != x_/usr; then
        SSLFLAGS="-I${with_openssl}/include"
    fi])

if test "x$with_openssl" = "x" ; then
    AC_PATH_PROG(PKG_CONFIG, pkg-config)
    if test "x$PKG_CONFIG" != x && test "x$PKG_CONFIG" != "xno" ; then
        if pkg-config openssl ; then
            SSLFLAGS="`$PKG_CONFIG --cflags openssl`"
        else
            AC_MSG_WARN([OpenSSL not supported by pkg-config, try --with-openssl instead])
        fi
    fi
fi

AC_MSG_CHECKING(for OpenSSL cflags)
AC_MSG_RESULT($SSLFLAGS)
CPPFLAGS="$SSLFLAGS $CPPFLAGS"

AC_CHECK_HEADER([openssl/x509.h],,AC_MSG_ERROR([unable to find openssl header files]))

AC_LANG([C++])

# C++ requirements
AC_CXX_NAMESPACES
AC_CXX_REQUIRE_STL

# Boost
BOOST_REQUIRE
BOOST_BIND
BOOST_LAMBDA
BOOST_PTR_CONTAINER
BOOST_STRING_ALGO
CPPFLAGS="$BOOST_CPPFLAGS $CPPFLAGS"

# log4shib settings (favor this version over the log4cpp code)
AC_PATH_PROG(LOG4SHIB_CONFIG,log4shib-config)
AC_ARG_WITH(log4shib,
    AS_HELP_STRING([--with-log4shib=PATH],[where log4shib-config is installed]),
    [
    LOG4SHIB_CONFIG="${with_log4shib}"
    if ! test -f "${LOG4SHIB_CONFIG}"; then
    	LOG4SHIB_CONFIG="${with_log4shib}/bin/log4shib-config"
    fi
    ])
if test -f "${LOG4SHIB_CONFIG}" ; then
    LIBS="`${LOG4SHIB_CONFIG} --libs` $LIBS"
    CPPFLAGS="`${LOG4SHIB_CONFIG} --cflags` $CPPFLAGS"
	AC_CHECK_HEADER([log4shib/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4shib header files]))
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[#include <log4shib/Category.hh>
#include <log4shib/CategoryStream.hh>]],
            [[log4shib::Category::getInstance("foo").errorStream() << log4shib::eol]])],
        [AC_DEFINE([OPENSAML_LOG4SHIB],[1],[Define to 1 if log4shib library is used.])],
        [AC_MSG_ERROR([unable to link with log4shib])])
else
    AC_MSG_WARN([log4shib-config not found, may need to use --with-log4shib option])
    AC_MSG_WARN([will look for original log4cpp library])
    
    # log4cpp settings
    AC_PATH_PROG(LOG4CPP_CONFIG,log4cpp-config)
    AC_ARG_WITH(log4cpp,
        AS_HELP_STRING([--with-log4cpp=PATH],[where log4cpp-config is installed]),
        [
        LOG4CPP_CONFIG="${with_log4cpp}"
        if ! test -f "${LOG4CPP_CONFIG}"; then
        	LOG4CPP_CONFIG="${with_log4cpp}/bin/log4cpp-config"
        fi
        ])
    if test -f "${LOG4CPP_CONFIG}"; then
        AC_MSG_WARN([will try to use log4cpp, note that most non-Internet2 supplied versions are not thread-safe])
        LIBS="`${LOG4CPP_CONFIG} --libs` $LIBS"
        CPPFLAGS="`${LOG4CPP_CONFIG} --cflags` $CPPFLAGS"
        AC_CHECK_HEADER([log4cpp/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4cpp header files]))
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM([[#include <log4cpp/Category.hh>
#include <log4cpp/CategoryStream.hh>]],
                [[log4cpp::Category::getInstance("foo").errorStream() << log4cpp::eol]])],
            [AC_DEFINE([OPENSAML_LOG4CPP],[1],[Define to 1 if log4cpp library is used.])],
            [AC_MSG_ERROR([unable to link with log4cpp, need version 1.0 or later])])
    else
        AC_MSG_ERROR([log4cpp-config not found, may need to use --with-log4cpp option])
    fi
fi

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
[#if  _XERCES_VERSION != 20600
int i = 0;
#else
#error cannot use version 2.6.0
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([Xerces-C v2.6.0 has bugs that inhibit use with signed XML, please use a newer version])])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <xercesc/util/PlatformUtils.hpp>]],[[xercesc::XMLPlatformUtils::Initialize()]])],
    ,[AC_MSG_ERROR([unable to link with Xerces])])

AC_MSG_CHECKING([whether Xerces XMLString::release(XMLByte**) exists])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <xercesc/util/XMLString.hpp>]],
    [[using namespace XERCES_CPP_NAMESPACE; XMLByte* buf=NULL; XMLString::release(&buf);]])],
    [AC_MSG_RESULT([yes])AC_DEFINE([OPENSAML_XERCESC_HAS_XMLBYTE_RELEASE],[1],[Define to 1 if Xerces XMLString includes XMLByte release.])],
    [AC_MSG_RESULT([no])])

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
    [#if XSEC_VERSION_MAJOR > 1 || (XSEC_VERSION_MAJOR == 1 && XSEC_VERSION_MEDIUM > 3)
int i = 0;
#else
#error need version 1.4.0 or later
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([XML-Security version 1.4.0 or greater is required.])])
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[#include <xsec/utils/XSECPlatformUtils.hpp>]],
            [[XSECPlatformUtils::Initialise()]])],,
        [AC_MSG_ERROR([unable to link with XML-Security])])

# XML-Tooling settings
AC_ARG_WITH(xmltooling,
    AS_HELP_STRING([--with-xmltooling=PATH],[where xmltooling is installed]),,
    [with_xmltooling=/usr])
if test x_$with_xmltooling != x_/usr; then
    CPPFLAGS="-I${with_xmltooling}/include $CPPFLAGS"
    DX_INCLUDE="${with_xmltooling}/include"
    LIBS="-L${with_xmltooling}/lib -lxmltooling $LIBS"
else
    LIBS="-lxmltooling $LIBS"
fi

AC_CHECK_HEADER([xmltooling/XMLToolingConfig.h],,AC_MSG_ERROR([unable to find xmltooling header files]))

AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/version.h>]],
        [[#if _XMLTOOLING_VERSION >= 10400
xmltooling::XMLToolingConfig::getConfig();
#else
#error Need XMLTooling version 1.4 or higher
#endif]])],
    ,[AC_MSG_ERROR([unable to link with XMLTooling, or version was too old])])

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

AX_CREATE_PKGCONFIG_INFO(,,[$LIBS -lsaml],[OpenSAML library])

AC_SUBST(DX_INCLUDE)
LIBTOOL="$LIBTOOL --silent"

# output packaging and makefiles
AC_OUTPUT
