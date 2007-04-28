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

/**
 * SAMLArtifact.cpp
 * 
 * Base class for SAML 1.x and 2.0 artifacts 
 */

#include "internal.h"
#include "binding/SAMLArtifact.h"

#include <xercesc/util/Base64.hpp>

using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1p {
        SAML_DLLLOCAL PluginManager<SAMLArtifact,string,const char*>::Factory SAMLArtifactType0001Factory; 
        SAML_DLLLOCAL PluginManager<SAMLArtifact,string,const char*>::Factory SAMLArtifactType0002Factory; 
    };

    namespace saml2p {
        SAML_DLLLOCAL PluginManager<SAMLArtifact,string,const char*>::Factory SAML2ArtifactType0004Factory; 
    };
};

void SAML_API opensaml::registerSAMLArtifacts()
{
    SAMLConfig& conf=SAMLConfig::getConfig();

    string typecode;
    typecode+=(char)0x0;
    typecode+=(char)0x1;
    conf.SAMLArtifactManager.registerFactory(typecode, saml1p::SAMLArtifactType0001Factory);
    typecode[1]=(char)0x2;
    conf.SAMLArtifactManager.registerFactory(typecode, saml1p::SAMLArtifactType0002Factory);
    typecode[1]=(char)0x4;
    conf.SAMLArtifactManager.registerFactory(typecode, saml2p::SAML2ArtifactType0004Factory);
}

const unsigned int SAMLArtifact::TYPECODE_LENGTH = 2;

// Basic constructor just decodes the string and saves it off.
// Subclasses will handle pulling it apart.

SAMLArtifact::SAMLArtifact(const char* s)
{
    unsigned int len=0;
    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(s),&len);
    if (!decoded)
        throw ArtifactException("Unable to decode base64 artifact.");
    XMLByte* ptr=decoded;
    while (len--)
        m_raw+= *ptr++;
    XMLString::release(&decoded);
}

string SAMLArtifact::encode() const
{
    unsigned int len=0;
    XMLByte* out=Base64::encode(reinterpret_cast<const XMLByte*>(m_raw.data()),m_raw.size(),&len);
    if (out) {
        string ret(reinterpret_cast<char*>(out),len);
        XMLString::release(&out);
        return ret;
    }
    return string();
}

SAMLArtifact* SAMLArtifact::parse(const char* s)
{
    // Decode and extract the type code first.
    unsigned int len=0;
    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(s),&len);
    if (!decoded)
        throw ArtifactException("Artifact parser unable to decode base64-encoded artifact.");
    
    string type;
    type+= decoded[0];
    type+= decoded[1];
    XMLString::release(&decoded);
    
    return SAMLConfig::getConfig().SAMLArtifactManager.newPlugin(type,s);
}

string SAMLArtifact::toHex(const string& s)
{
    static char DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    string::size_type len = s.length();
    string ret;
    
    // two characters form the hex value.
    for (string::size_type i=0; i < len; i++) {
        ret+=(DIGITS[((unsigned char)(0xF0 & s[i])) >> 4 ]);
        ret+=(DIGITS[0x0F & s[i]]);
    }
    return ret;
}
