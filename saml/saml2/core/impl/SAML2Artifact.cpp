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
 * SAML2Artifact.cpp
 * 
 * Base class for SAML 2.0 artifacts 
 */

#include "internal.h"
#include "saml2/core/SAML2Artifact.h"

using namespace opensaml::saml2p;

const unsigned int SAML2Artifact::INDEX_LENGTH = 2;

int SAML2Artifact::getEndpointIndex() const
{
    int index=0;
    if (m_raw.size()>=TYPECODE_LENGTH+INDEX_LENGTH) {
        index = (16 * static_cast<int>(m_raw[TYPECODE_LENGTH])) + static_cast<int>(m_raw[TYPECODE_LENGTH+1]); 
    }
    return index;
}
