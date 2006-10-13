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
 * MetadataKeyInfoIterator.h
 * 
 * Adapter between SAML metadata and TrustEngine KeyInfoIterator interface.
 */

#ifndef __saml_keyiter_h__
#define __saml_keyiter_h__

#include <saml/saml2/metadata/Metadata.h>

#include <xmltooling/security/TrustEngine.h>

namespace opensaml {
    
    /**
     * Adapter between SAML metadata and TrustEngine KeyInfoIterator interface. 
     */
    class SAML_API MetadataKeyInfoIterator : public xmltooling::TrustEngine::KeyInfoIterator
    {
        const std::vector<saml2md::KeyDescriptor*>& m_keys;
        std::vector<saml2md::KeyDescriptor*>::const_iterator m_iter;
        
        void advance() {
            while (hasNext()) {
                const XMLCh* use=(*m_iter)->getUse();
                if ((!use || !*use || XMLString::equals(use,saml2md::KeyDescriptor::KEYTYPE_SIGNING)) && (*m_iter)->getKeyInfo())
                    return;
                m_iter++;
            }
        }
        
    public:
        MetadataKeyInfoIterator(const saml2md::RoleDescriptor& role) : m_keys(role.getKeyDescriptors()) {
            m_iter=m_keys.begin();
            advance();
        }

        virtual ~MetadataKeyInfoIterator() {}
        
        /**
         * Indicates whether additional KeyInfo objects are available.
         * 
         * @return true iff another KeyInfo object can be fetched
         */
        virtual bool hasNext() const {
            return m_iter!=m_keys.end();
        }
        
        /**
         * Returns the next KeyInfo object available.
         * 
         * @return the next KeyInfo object, or NULL if none are left
         */
        virtual const xmlsignature::KeyInfo* next() {
            xmlsignature::KeyInfo* ret = (*m_iter)->getKeyInfo();
            m_iter++;
            advance();
            return ret;
        }
    };
};

#endif /* __saml_keyiter_h__ */
