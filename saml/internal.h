/*
 *  Copyright 2001-2007 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  internal.h - internally visible classes
 */

#ifndef __saml_internal_h__
#define __saml_internal_h__

#ifdef WIN32
# define _CRT_SECURE_NO_DEPRECATE 1
# define _CRT_NONSTDC_NO_DEPRECATE 1
#endif

// Export public APIs
#define SAML_EXPORTS

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include "base.h"
#include "SAMLConfig.h"

#include <limits.h>

using namespace xercesc;

// C99 defines LLONG_MIN, LLONG_MAX and ULLONG_MAX, but this part of
// C99 is not yet included into the C++ standard.
// GCC defines LONG_LONG_MIN, LONG_LONG_MAX and ULONG_LONG_MAX.
// Some compilers (such as Comeau C++ up to and including version 4.3.3)
// define nothing.  In this last case we make a reasonable guess.
#ifndef LLONG_MIN
#if defined(LONG_LONG_MIN)
#define LLONG_MIN LONG_LONG_MIN
#elif SIZEOF_LONG_LONG == 8
#define LLONG_MIN 0x8000000000000000LL
#endif
#endif
 
#ifndef LLONG_MAX
#if defined(LONG_LONG_MAX)
#define LLONG_MAX LONG_LONG_MAX
#elif SIZEOF_LONG_LONG == 8
#define LLONG_MAX 0x7fffffffffffffffLL
#endif
#endif
 
#ifndef ULLONG_MAX
#if defined(ULONG_LONG_MAX)
#define ULLONG_MAX ULONG_LONG_MAX
#elif SIZEOF_UNSIGNED_LONG_LONG == 8
#define ULLONG_MAX 0xffffffffffffffffULL
#endif
#endif

#if SIZEOF_TIME_T == 8
# define SAMLTIME_MAX LLONG_MAX
#elif SIZEOF_TIME_T == 4
# define SAMLTIME_MAX LONG_MAX
#endif

#define SAML_LOGCAT "OpenSAML"

namespace opensaml {
    
    /// @cond OFF
    class SAMLInternalConfig : public SAMLConfig
    {
    public:
        SAMLInternalConfig() {}

        static SAMLInternalConfig& getInternalConfig();

        // global per-process setup and shutdown of runtime
        bool init(bool initXMLTooling=true);
        void term(bool termXMLTooling=true);

        void generateRandomBytes(void* buf, unsigned int len);
        void generateRandomBytes(std::string& buf, unsigned int len);
        XMLCh* generateIdentifier();
        std::string hashSHA1(const char* data, bool toHex=false);
    private:
    };
    /// @endcond

};

#endif /* __saml_internal_h__ */
