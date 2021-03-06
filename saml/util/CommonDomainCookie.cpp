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
 * CommonDomainCookie.cpp
 * 
 * Helper class for maintaining discovery cookie. 
 */

#include "internal.h"
#include "util/CommonDomainCookie.h"

#include <boost/algorithm/string.hpp>
#include <xercesc/util/Base64.hpp>
#include <xsec/framework/XSECDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

const char CommonDomainCookie::CDCName[] = "_saml_idp";

CommonDomainCookie::CommonDomainCookie(const char* cookie)
{
    if (!cookie)
        return;

    // Copy it so we can URL-decode it.
    char* b64=strdup(cookie);
    XMLToolingConfig::getConfig().getURLEncoder()->decode(b64);

    // Chop it up and save off elements.
    split(m_list, b64, is_space(), algorithm::token_compress_on);
    free(b64);

    // Remove empty elements.
    m_list.erase(remove(m_list.begin(), m_list.end(), ""), m_list.end());

    // Now Base64 decode the list elements, overwriting them.
    XMLSize_t len;
    for (vector<string>::iterator i = m_list.begin(); i != m_list.end(); ++i) {
        trim(*i);
        XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(i->c_str()),&len);
        if (decoded && *decoded) {
            i->assign(reinterpret_cast<char*>(decoded));
            XMLString::release((char**)&decoded);
        }
    }
}

CommonDomainCookie::~CommonDomainCookie()
{
}

const vector<string>& CommonDomainCookie::get() const
{
    return m_list;
}

const char* CommonDomainCookie::set(const char* entityID)
{
    // First remove the IdP from the list.
    m_list.erase(remove(m_list.begin(), m_list.end(), entityID), m_list.end());
    
    // Append it to the end.
    m_list.push_back(entityID);
    
    // Now rebuild the delimited list.
    XMLSize_t len;
    string delimited;
    for (vector<string>::const_iterator j = m_list.begin(); j != m_list.end(); ++j) {
        
        XMLByte* b64 = Base64::encode(reinterpret_cast<const XMLByte*>(j->c_str()), j->length(), &len);
        if (b64) {
            XMLByte *pos, *pos2;
            for (pos = b64, pos2 = b64; *pos2; ++pos2)
                if (isgraph(*pos2))
                    *pos++ = *pos2;
            *pos = 0;
        
            if (!delimited.empty())
                delimited += ' ';
            delimited += reinterpret_cast<char*>(b64);
            XMLString::release((char**)&b64);
        }
    }
    
    m_encoded = XMLToolingConfig::getConfig().getURLEncoder()->encode(delimited.c_str());
    return m_encoded.c_str();
}
