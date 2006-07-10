/*
 *  Copyright 2001-2006 Internet2
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

/**
 * @file saml/base.h
 * 
 * Base header file definitions
 * Must be included prior to including any other header
 */

#ifndef __saml_base_h__
#define __saml_base_h__

#include <xmltooling/base.h>

// Windows and GCC4 Symbol Visibility Macros
#ifdef WIN32
  #define SAML_IMPORT __declspec(dllimport)
  #define SAML_EXPORT __declspec(dllexport)
  #define SAML_DLLLOCAL
  #define SAML_DLLPUBLIC
#else
  #define SAML_IMPORT
  #ifdef GCC_HASCLASSVISIBILITY
    #define SAML_EXPORT __attribute__ ((visibility("default")))
    #define SAML_DLLLOCAL __attribute__ ((visibility("hidden")))
    #define SAML_DLLPUBLIC __attribute__ ((visibility("default")))
  #else
    #define SAML_EXPORT
    #define SAML_DLLLOCAL
    #define SAML_DLLPUBLIC
  #endif
#endif

// Define SAML_API for DLL builds
#ifdef SAML_EXPORTS
  #define SAML_API SAML_EXPORT
#else
  #define SAML_API SAML_IMPORT
#endif

// Throwable classes must always be visible on GCC in all binaries
#ifdef WIN32
  #define SAML_EXCEPTIONAPI(api) api
#elif defined(GCC_HASCLASSVISIBILITY)
  #define SAML_EXCEPTIONAPI(api) SAML_EXPORT
#else
  #define SAML_EXCEPTIONAPI(api)
#endif

#endif /* __saml_base_h__ */
