/* config_win32.h.  Copied from a ./configure on Unix */

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define to 1 if you have the `gmtime_r' function. */
/* #undef HAVE_GMTIME_R */

/* Define to 1 if you have the <inttypes.h> header file. */
/* #undef HAVE_INTTYPES_H */

/* Define if log4shib library is used. */
#define OPENSAML_LOG4SHIB 1

/* Define if log4cpp library is used. */
/* #undef OPENSAML_LOG4CPP */

#include <xercesc/util/XercesVersion.hpp>

#if (XERCES_VERSION_MAJOR < 3)
# define OPENSAML_XERCESC_HAS_XMLBYTE_RELEASE 1
#endif

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* define if the compiler implements namespaces */
#define HAVE_NAMESPACES 1

/* Define to 1 if you have the <stdint.h> header file. */
/* #undef HAVE_STDINT_H */

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the <strings.h> header file. */
/* #undef HAVE_STRINGS_H */

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
/* #undef HAVE_UNISTD_H */

/* Name of package */
#define PACKAGE "opensaml"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://bugs.internet2.edu/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "opensaml"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "opensaml 2.4"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "opensaml"

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.4"

/* Define to the necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Version number of package */
#define VERSION "2.4"

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `unsigned' if <sys/types.h> does not define. */
/* #undef size_t */

/* The size of a `time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 8

