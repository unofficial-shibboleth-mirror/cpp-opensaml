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
 * SAMLArtifactType0002.cpp
 * 
 * Type 0x0002 SAML 1.x artifact class.
 */

#include "internal.h"
#include "saml1/binding/SAMLArtifactType0002.h"

using namespace opensaml::saml1p;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1p {
        SAMLArtifact* SAML_DLLLOCAL SAMLArtifactType0002Factory(const char* const & s, bool)
        {
            return new SAMLArtifactType0002(s);
        }
    }
};

const unsigned int SAMLArtifactType0002::HANDLE_LENGTH = 20;

SAMLArtifactType0002::SAMLArtifactType0002(const SAMLArtifactType0002& src) : SAMLArtifact(src)
{
}

SAMLArtifactType0002::SAMLArtifactType0002(const char* s) : SAMLArtifact(s)
{
    // The base class does the work, we just do the checking.
    if (m_raw.size() <= TYPECODE_LENGTH + HANDLE_LENGTH)
        throw ArtifactException("Type 0x0002 artifact given artifact of incorrect length.");
    else if (m_raw[0] != 0x0 || m_raw[1] != 0x2)
        throw ArtifactException(
            string("Type 0x0002 artifact given artifact of invalid type (") + toHex(getTypeCode()) + ")."
            );
}

SAMLArtifactType0002::SAMLArtifactType0002(const string& sourceLocation)
{
    if (sourceLocation.empty())
        throw ArtifactException("Type 0x0002 artifact with empty source location.");
    m_raw+=(char)0x0;
    m_raw+=(char)0x2;
    char buf[HANDLE_LENGTH];
    SAMLConfig::getConfig().generateRandomBytes(buf,HANDLE_LENGTH);
    for (int i=0; i<HANDLE_LENGTH; i++)
        m_raw+=buf[i];
    m_raw+=sourceLocation;
}

SAMLArtifactType0002::SAMLArtifactType0002(const string& sourceLocation, const string& handle)
{
    if (sourceLocation.empty())
        throw ArtifactException("Type 0x0002 artifact with empty source location.");
    if (handle.size()!=HANDLE_LENGTH)
        throw ArtifactException("Type 0x0002 artifact with handle of incorrect length.");
    m_raw+=(char)0x0;
    m_raw+=(char)0x2;
    m_raw.append(handle,0,HANDLE_LENGTH);
    m_raw+=sourceLocation;
}

SAMLArtifactType0002::~SAMLArtifactType0002()
{
}

SAMLArtifactType0002* SAMLArtifactType0002::clone() const
{
    return new SAMLArtifactType0002(*this);
}

string SAMLArtifactType0002::getMessageHandle() const
{
    return m_raw.substr(TYPECODE_LENGTH, HANDLE_LENGTH);    // bytes 3-22
}

string SAMLArtifactType0002::getSource() const
{
    return m_raw.c_str() + TYPECODE_LENGTH + HANDLE_LENGTH; // bytes 23-terminating null
}
