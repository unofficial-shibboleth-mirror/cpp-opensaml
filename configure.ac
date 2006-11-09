AC_PREREQ([2.50])
AC_INIT([opensaml], [2.0], [mace-opensaml-users@internet2.edu], [saml])
AM_CONFIG_HEADER(config.h)
#AM_CONFIG_HEADER(saml/config_pub.h)
AM_INIT_AUTOMAKE([opensaml], [2.0])

sinclude(doxygen.m4)

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
    AC_HELP_STRING(--enable-debug, [Have GCC compile with symbols (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -Wall -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -Wall -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -Wall -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -Wall -O2 -DNDEBUG"
fi

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])

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

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([strchr strdup strstr])

AC_CHECK_SIZEOF(time_t)

# libcurl settings
AC_PATH_PROG(CURL_CONFIG,curl-config)
AC_ARG_WITH(curl,
    AC_HELP_STRING([--with-curl=PATH], [where curl-config is installed]),
    [
    CURL_CONFIG="${with_curl}"
    if ! test -f "${CURL_CONFIG}" ; then
    	CURL_CONFIG="${with_curl}/bin/curl-config"
    fi
    ])
if test -f "${CURL_CONFIG}" ; then
    LDFLAGS="`${CURL_CONFIG} --libs` $LDFLAGS"
    CPPFLAGS="`${CURL_CONFIG} --cflags` $CPPFLAGS"
else
    AC_MSG_ERROR([curl-config not found, may need to use --with-curl option])
fi
AC_CHECK_HEADER([curl/curl.h],,AC_MSG_ERROR([unable to find libcurl header files]))
AC_CHECK_LIB([curl],[curl_global_init],,AC_MSG_ERROR([unable to link with libcurl]))
AC_MSG_CHECKING([for CURLOPT_SSL_CTX_FUNCTION in curl.h])
AC_EGREP_HEADER([CURLOPT_SSL_CTX_FUNCTION], [curl/curl.h],
		[AC_MSG_RESULT(yes)],
		[AC_MSG_ERROR([need libcurl that supports CURLOPT_SSL_CTX_FUNCTION])])

# zlib settings
AC_ARG_WITH(zlib,
	AC_HELP_STRING([--with-zlib=PATH], [where zlib is installed]),
	[
		if test -d "$withval"; then
			CPPFLAGS="${CPPFLAGS} -I$withval/include"
			LDFLAGS="${LDFLAGS} -L$withval/lib"
		fi
	]
)
AC_CHECK_HEADER(zlib.h,
	AC_CHECK_LIB(z, deflateInit2, ,
		AC_MSG_ERROR([zlib library not found, may need to use --with-zlib option])),
	AC_MSG_ERROR([zlib headers not found, may need to use --with-zlib option]))

AC_LANG(C++)

# C++ requirements
AC_CXX_REQUIRE_STL
AC_CXX_NAMESPACES

# log4cpp settings
AC_PATH_PROG(LOG4CPP_CONFIG,log4cpp-config)
AC_ARG_WITH(log4cpp,
    AC_HELP_STRING([--with-log4cpp=PATH], [where log4cpp-config is installed]),
    [
    LOG4CPP_CONFIG="${with_log4cpp}"
    if ! test -f "${LOG4CPP_CONFIG}" ; then
    	LOG4CPP_CONFIG="${with_log4cpp}/bin/log4cpp-config"
    fi
    ])
if test -f "${LOG4CPP_CONFIG}"; then
    LDFLAGS="`${LOG4CPP_CONFIG} --libs` $LDFLAGS"
    CPPFLAGS="`${LOG4CPP_CONFIG} --cflags` $CPPFLAGS"
else
    AC_MSG_ERROR([log4cpp-config not found, may need to use --with-log4cpp option])
    LIBS="-llog4cpp $LIBS"
fi
AC_CHECK_HEADER([log4cpp/Category.hh],,AC_MSG_ERROR([unable to find log4cpp header files]))
AC_CHECK_HEADER([log4cpp/PropertyConfigurator.hh],,AC_MSG_ERROR([you need at least log4cpp 0.3.x]))
AC_TRY_LINK(
	[#include <log4cpp/Category.hh>],
	[log4cpp::Category::getInstance("foo")],
	[AC_DEFINE(HAVE_LIBLOG4CPP,1,[Define if log4cpp library was found])],
	[AC_MSG_ERROR([unable to link with log4cpp])])

# Xerces settings
AC_ARG_WITH(xerces, 
            AC_HELP_STRING([--with-xerces=PATH], [where xerces-c is installed]),
            [if test x_$with_xerces != x_/usr; then
                LDFLAGS="-L${with_xerces}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xerces}/include $CPPFLAGS"
            fi])
LIBS="-lxerces-c $LIBS"
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
    [AC_MSG_FAILURE([Xerces-C v2.6.0 has bugs that inhibit use with signed XML, please use special 2.6.1 tarball provided by Shibboleth Project])])
AC_TRY_LINK(
    [#include <xercesc/util/PlatformUtils.hpp>],
    [xercesc::XMLPlatformUtils::Initialize()],
    [AC_DEFINE(HAVE_LIBXERCESC,1,[Define if Xerces-C library was found])],
    [AC_MSG_ERROR([unable to link with Xerces])])


# XML-Security settings
AC_ARG_WITH(xmlsec,
    AC_HELP_STRING([--with-xmlsec=PATH], [where xmlsec is installed]),
    [if test x_$with_xmlsec != x_/usr; then
        LDFLAGS="-L${with_xmlsec}/lib $LDFLAGS"
        CPPFLAGS="-I${with_xmlsec}/include $CPPFLAGS"
    fi])
LIBS="-lxml-security-c $LIBS"
AC_CHECK_HEADER([xsec/utils/XSECPlatformUtils.hpp],,AC_MSG_ERROR([unable to find xmlsec header files]))
AC_TRY_LINK(
    [#include <xsec/utils/XSECPlatformUtils.hpp>],
    [XSECPlatformUtils::Initialise()],
    [AC_DEFINE(HAVE_LIBXSEC,1,[Define if XML-Sec library was found])],
    [AC_MSG_ERROR([unable to link with xmlsec library])]
    )

# XML-Tooling settings
AC_ARG_WITH(xmltooling,
    AC_HELP_STRING([--with-xmltooling=PATH], [where xmltooling is installed]),
    [if test x_$with_xmltooling != x_/usr; then
        LDFLAGS="-L${with_xmltooling}/lib $LDFLAGS"
        CPPFLAGS="-I${with_xmltooling}/include $CPPFLAGS"
        DX_INCLUDE="${with_xmltooling}/include"
    fi])
LIBS="-lxmltooling $LIBS"
AC_CHECK_HEADER([xmltooling/XMLToolingConfig.h],,AC_MSG_ERROR([unable to find xmltooling header files]))
AC_TRY_LINK(
    [#include <xmltooling/XMLToolingConfig.h>],
    [xmltooling::XMLToolingConfig::getConfig().init()],
    [AC_DEFINE(HAVE_LIBXMLTOOLING,1,[Define if XML-Tooling library was found])],
    [AC_MSG_ERROR([unable to link with xmltooling library])]
    )

# Does the STL in use help or screw us?
AC_TRY_LINK(
    [#include <string>],
    [std::basic_string<unsigned short> foo; foo=foo+(unsigned short)65],
    [AC_DEFINE(HAVE_GOOD_STL,1,
        [Define if you have an STL implementation that supports useful string specialization.])],
    )

# Check for unit test support
CXXTEST="/usr/bin/cxxtestgen.pl"
CXXTESTFLAGS=""
AC_ARG_WITH(cxxtest,
            AC_HELP_STRING([--with-cxxtest=PATH], [where cxxtest is installed]),
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

AC_SUBST(DX_INCLUDE)
LIBTOOL="$LIBTOOL --silent"

# output makefiles
AC_OUTPUT(Makefile saml/Makefile samltest/Makefile schemas/Makefile)
