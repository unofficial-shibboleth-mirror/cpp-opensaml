/*
 *  Copyright 2001-2009 Internet2
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
 * saml/version.h
 * 
 * Library version macros and constants 
 */

#ifndef __saml_version_h__
#define __saml_version_h__

// This is all based on Xerces, on the theory it might be useful to
// support this kind of stuff in the future. If they ever yank some
// of this stuff, it can be copied into here.

#include <xercesc/util/XercesVersion.hpp>

// ---------------------------------------------------------------------------
// V E R S I O N   S P E C I F I C A T I O N

/**
 * MODIFY THESE NUMERIC VALUES TO COINCIDE WITH OPENSAML VERSION
 * AND DO NOT MODIFY ANYTHING ELSE IN THIS VERSION HEADER FILE
 */

#define OPENSAML_VERSION_MAJOR 2
#define OPENSAML_VERSION_MINOR 4
#define OPENSAML_VERSION_REVISION 1

/** DO NOT MODIFY BELOW THIS LINE */

/**
 * MAGIC THAT AUTOMATICALLY GENERATES THE FOLLOWING:
 *
 *	gOpenSAMLVersionStr, gOpenSAMLFullVersionStr, gOpenSAMLMajVersion, gOpenSAMLMinVersion, gOpenSAMLRevision
 */

// ---------------------------------------------------------------------------
// V E R S I O N   I N F O R M A T I O N

// OpenSAML version strings; these particular macros cannot be used for
// conditional compilation as they are not numeric constants

#define OPENSAML_FULLVERSIONSTR INVK_CAT3_SEP_UNDERSCORE(OPENSAML_VERSION_MAJOR,OPENSAML_VERSION_MINOR,OPENSAML_VERSION_REVISION)
#define OPENSAML_FULLVERSIONDOT INVK_CAT3_SEP_PERIOD(OPENSAML_VERSION_MAJOR,OPENSAML_VERSION_MINOR,OPENSAML_VERSION_REVISION)
#define OPENSAML_FULLVERSIONNUM INVK_CAT3_SEP_NIL(OPENSAML_VERSION_MAJOR,OPENSAML_VERSION_MINOR,OPENSAML_VERSION_REVISION)
#define OPENSAML_VERSIONSTR     INVK_CAT2_SEP_UNDERSCORE(OPENSAML_VERSION_MAJOR,OPENSAML_VERSION_MINOR)

const char* const    gOpenSAMLVersionStr = OPENSAML_VERSIONSTR;
const char* const    gOpenSAMLFullVersionStr = OPENSAML_FULLVERSIONSTR;
const unsigned int   gOpenSAMLMajVersion = OPENSAML_VERSION_MAJOR;
const unsigned int   gOpenSAMLMinVersion = OPENSAML_VERSION_MINOR;
const unsigned int   gOpenSAMLRevision   = OPENSAML_VERSION_REVISION;

// OpenSAML version numeric constants that can be used for conditional
// compilation purposes.

#define _OPENSAML_VERSION CALC_EXPANDED_FORM (OPENSAML_VERSION_MAJOR,OPENSAML_VERSION_MINOR,OPENSAML_VERSION_REVISION)

#endif /* __saml_version_h__ */
