/*
 *  Copyright 2001-2010 Internet2
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
 * @file saml/encryption/EncryptedKeyResolver.h
 * 
 * SAML-specific encrypted key resolver.
 */

#ifndef __saml_enckeyres_h__
#define __saml_enckeyres_h__

#include <saml/base.h>
#include <xmltooling/encryption/EncryptedKeyResolver.h>

namespace opensaml {

    namespace saml2 {
        class SAML_API EncryptedElementType;
    };

    /**
     * SAML-specific encrypted key resolver.
     * 
     * SAML allows placement of keys alongside the encrypted data. This resolver
     * recognizes the implied placement.
     */
    class SAML_API EncryptedKeyResolver : public xmlencryption::EncryptedKeyResolver
    {
    public:
        /**
         * Constructor.
         * 
         * @param ref   reference to encrypted element
         */
        EncryptedKeyResolver(const saml2::EncryptedElementType& ref);
        
        virtual ~EncryptedKeyResolver();

        const xmlencryption::EncryptedKey* resolveKey(const xmlencryption::EncryptedData& encryptedData, const XMLCh* recipient=nullptr) const;
     
    protected:
        /** Reference to encrypted element. */
        const saml2::EncryptedElementType& m_ref;
    };

};

#endif /* __saml_enckeyres_h__ */
