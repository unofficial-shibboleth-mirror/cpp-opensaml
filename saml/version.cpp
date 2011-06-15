/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * version.cpp
 * 
 * Library version macros and constants.
 */

#include "internal.h"
#include "version.h"

SAML_API const char* const    gOpenSAMLVersionStr = OPENSAML_VERSIONSTR;
SAML_API const char* const    gOpenSAMLFullVersionStr = OPENSAML_FULLVERSIONSTR;
SAML_API const char* const    gOpenSAMLDotVersionStr = OPENSAML_FULLVERSIONDOT;
SAML_API const unsigned int   gOpenSAMLMajVersion = OPENSAML_VERSION_MAJOR;
SAML_API const unsigned int   gOpenSAMLMinVersion = OPENSAML_VERSION_MINOR;
SAML_API const unsigned int   gOpenSAMLRevision   = OPENSAML_VERSION_REVISION;
