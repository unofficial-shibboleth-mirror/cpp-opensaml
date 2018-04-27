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
 * @file saml/saml2/metadata/MetadataCredentialCriteria.h
 * 
 * Metadata-based CredentialCriteria subclass.
 */

#ifndef __saml_metacrit_h__
#define __saml_metacrit_h__

#include <saml/base.h>
#include <xmltooling/security/CredentialCriteria.h>

namespace opensaml {
    namespace saml2md {
        
        /**
         * Metadata-based CredentialCriteria subclass.
         */
        class SAML_API MetadataCredentialCriteria : public xmltooling::CredentialCriteria
        {
        public:
            /**
             * Constructor.
             *
             * @param role      source of metadata-supplied credentials
             */
            MetadataCredentialCriteria(const RoleDescriptor& role);
    
            virtual ~MetadataCredentialCriteria() {}
            
            /**
             * Return the metadata role associated with the credentials.
             *
             * @return the associated metadata role
             */
            const RoleDescriptor& getRole() const {
                return m_role;
            }

            /**
             * Get whether the candidate credential matches the criteria.
             *
             * @param credential candidate
             */
            bool matches(const xmltooling::Credential& credential) const;

        private:
            const RoleDescriptor& m_role;
        };
    };
};

#endif /* __saml_metacrit_h__ */
