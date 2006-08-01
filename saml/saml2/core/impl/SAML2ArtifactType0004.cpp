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
 * SAML2ArtifactType0004.cpp
 * 
 * Type 0x0004 SAML 2.0 artifact class 
 */

#include "internal.h"
#include "saml2/core/SAML2ArtifactType0004.h"

using namespace opensaml::saml2p;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2p {
        SAMLArtifact* SAML_DLLLOCAL SAML2ArtifactType0004Factory(const char* const & s)
        {
            return new SAML2ArtifactType0004(s);
        }
    }
};

const unsigned int SAML2ArtifactType0004::SOURCEID_LENGTH = 20;
const unsigned int SAML2ArtifactType0004::HANDLE_LENGTH = 20;

SAML2ArtifactType0004::SAML2ArtifactType0004(const char* s) : SAML2Artifact(s)
{
    // The base class does the work, we just do the checking.
    if (m_raw.size() != TYPECODE_LENGTH + INDEX_LENGTH + SOURCEID_LENGTH + HANDLE_LENGTH)
        throw ArtifactException("Type 0x0004 artifact is of incorrect length.");
    else if (m_raw[0] != 0x0 || m_raw[1] != 0x4)
        throw ArtifactException(
            string("Type 0x0004 artifact given an artifact of invalid type (") + toHex(getTypeCode()) + ")."
            );
}

SAML2ArtifactType0004::SAML2ArtifactType0004(const string& sourceid, int index)
{
    if (sourceid.size()!=SOURCEID_LENGTH)
        throw ArtifactException("Type 0x0004 artifact sourceid of incorrect length.");
    if (index < 0 || index > (1 << 16)-1)
        throw ArtifactException("Type 0x0004 artifact index is invalid.");
    m_raw+=(char)0x0;
    m_raw+=(char)0x4;
    m_raw+=(char)(index / 256);
    m_raw+=(char)(index % 256);
    m_raw.append(sourceid,0,SOURCEID_LENGTH);
    char buf[HANDLE_LENGTH];
    SAMLConfig::getConfig().generateRandomBytes(buf,HANDLE_LENGTH);
    for (int i=0; i<HANDLE_LENGTH; i++)
        m_raw+=buf[i];
}

SAML2ArtifactType0004::SAML2ArtifactType0004(const string& sourceid, int index, const string& handle)
{
    if (sourceid.size()!=SOURCEID_LENGTH)
        throw ArtifactException("Type 0x0004 artifact sourceid of incorrect length.");
    if (index < 0 || index > (1 << 16)-1)
        throw ArtifactException("Type 0x0004 artifact index is invalid.");
    if (handle.size()!=HANDLE_LENGTH)
        throw ArtifactException("Type 0x0004 artifact message handle of incorrect length.");
    m_raw+=(char)0x0;
    m_raw+=(char)0x4;
    m_raw+=(char)(index / 256);
    m_raw+=(char)(index % 256);
    m_raw.append(sourceid,0,SOURCEID_LENGTH);
    m_raw.append(handle,0,HANDLE_LENGTH);
}
