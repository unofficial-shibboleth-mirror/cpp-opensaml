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
 * @file saml/saml2/metadata/MetadataCredentialContext.h
 * 
 * Metadata-based CredentialContext subclass.
 */

#ifndef __saml_metacredctx_h__
#define __saml_metacredctx_h__

#include <saml/base.h>
#include <xmltooling/security/KeyInfoCredentialContext.h>

namespace opensaml {
    namespace saml2md {
        
        class SAML_API KeyDescriptor;

        /**
         * Metadata-based CredentialContext subclass.
         */
        class SAML_API MetadataCredentialContext : public xmltooling::KeyInfoCredentialContext
        {
        public:
            /**
             * Constructor.
             *
             * @param descriptor    source of metadata-supplied credential
             */
            MetadataCredentialContext(const KeyDescriptor& descriptor);
    
            virtual ~MetadataCredentialContext();
            
            /**
             * Return the KeyDescriptor associated with the credential.
             *
             * @return the associated KeyDescriptor
             */
            const KeyDescriptor& getKeyDescriptor() const;

        private:
            const KeyDescriptor& m_descriptor;
        };
    };
};

#endif /* __saml_metacredctx_h__ */
