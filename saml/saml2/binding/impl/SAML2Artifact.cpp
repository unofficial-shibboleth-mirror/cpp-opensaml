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
 * SAML2Artifact.cpp
 * 
 * Base class for SAML 2.0 artifacts.
 */

#include "internal.h"
#include "saml2/binding/SAML2Artifact.h"

using namespace opensaml::saml2p;

const unsigned int SAML2Artifact::INDEX_LENGTH = 2;

SAML2Artifact::SAML2Artifact()
{
}

SAML2Artifact::SAML2Artifact(const char* s) : SAMLArtifact(s)
{
}

SAML2Artifact::SAML2Artifact(const SAML2Artifact& src) : SAMLArtifact(src)
{
}

SAML2Artifact::~SAML2Artifact()
{
}

int SAML2Artifact::getEndpointIndex() const
{
    int index=0;
    if (m_raw.size()>=TYPECODE_LENGTH+INDEX_LENGTH) {
        index = (16 * static_cast<int>(m_raw[TYPECODE_LENGTH])) + static_cast<int>(m_raw[TYPECODE_LENGTH+1]); 
    }
    return index;
}
