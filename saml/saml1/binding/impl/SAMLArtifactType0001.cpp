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
 * SAMLArtifactType0001.cpp
 * 
 * Type 0x0001 SAML 1.x artifact class.
 */

#include "internal.h"
#include "saml1/binding/SAMLArtifactType0001.h"

using namespace opensaml::saml1p;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1p {
        SAMLArtifact* SAML_DLLLOCAL SAMLArtifactType0001Factory(const char* const & s)
        {
            return new SAMLArtifactType0001(s);
        }
    }
};

const unsigned int SAMLArtifactType0001::SOURCEID_LENGTH = 20;
const unsigned int SAMLArtifactType0001::HANDLE_LENGTH = 20;

SAMLArtifactType0001::SAMLArtifactType0001(const SAMLArtifactType0001& src) : SAMLArtifact(src)
{
}

SAMLArtifactType0001::SAMLArtifactType0001(const char* s) : SAMLArtifact(s)
{
    // The base class does the work, we just do the checking.
    if (m_raw.size() != TYPECODE_LENGTH + SOURCEID_LENGTH + HANDLE_LENGTH)
        throw ArtifactException("Type 0x0001 artifact is of incorrect length.");
    else if (m_raw[0] != 0x0 || m_raw[1] != 0x1)
        throw ArtifactException(
            string("Type 0x0001 artifact given an artifact of invalid type (") + toHex(getTypeCode()) + ")."
            );
}

SAMLArtifactType0001::SAMLArtifactType0001(const string& sourceid)
{
    if (sourceid.size()!=SOURCEID_LENGTH)
        throw ArtifactException("Type 0x0001 artifact sourceid of incorrect length.");
    m_raw+=(char)0x0;
    m_raw+=(char)0x1;
    m_raw.append(sourceid,0,SOURCEID_LENGTH);
    char buf[HANDLE_LENGTH];
    SAMLConfig::getConfig().generateRandomBytes(buf,HANDLE_LENGTH);
    for (int i=0; i<HANDLE_LENGTH; i++)
        m_raw+=buf[i];
}

SAMLArtifactType0001::SAMLArtifactType0001(const string& sourceid, const string& handle)
{
    if (sourceid.size()!=SOURCEID_LENGTH)
        throw ArtifactException("Type 0x0001 artifact sourceid of incorrect length.");
    if (handle.size()!=HANDLE_LENGTH)
        throw ArtifactException("Type 0x0001 artifact assertion handle of incorrect length.");
    m_raw+=(char)0x0;
    m_raw+=(char)0x1;
    m_raw.append(sourceid,0,SOURCEID_LENGTH);
    m_raw.append(handle,0,HANDLE_LENGTH);
}

SAMLArtifactType0001::~SAMLArtifactType0001()
{
}

SAMLArtifactType0001* SAMLArtifactType0001::clone() const
{
    return new SAMLArtifactType0001(*this);
}

string SAMLArtifactType0001::getSource() const
{
    return toHex(getSourceID());
}

string SAMLArtifactType0001::getSourceID() const
{
    return m_raw.substr(TYPECODE_LENGTH,SOURCEID_LENGTH);                   // bytes 3-22
}

string SAMLArtifactType0001::getMessageHandle() const
{
    return m_raw.substr(TYPECODE_LENGTH+SOURCEID_LENGTH, HANDLE_LENGTH);    // bytes 23-42
}
