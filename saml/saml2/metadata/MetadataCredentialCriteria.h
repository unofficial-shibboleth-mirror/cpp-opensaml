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
 * @file saml/saml2/metadata/MetadataCredentialCriteria.h
 * 
 * Metadata-based CredentialCriteria subclass.
 */

#ifndef __saml_metacred_h__
#define __saml_metacred_h__

#include <saml/base.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/security/CredentialCriteria.h>

namespace opensaml {
    namespace saml2md {
        
        /**
         * Metadata-based CredentialCriteria subclass.
         */
        class SAML_API MetadataCredentialCriteria : public xmltooling::CredentialCriteria
        {
        public:
            /*
             * Constructor.
             *
             * @param role      source of metadata-supplied credentials
             */
            MetadataCredentialCriteria(const RoleDescriptor& role) : m_role(role) {
                const EntityDescriptor* entity = dynamic_cast<const EntityDescriptor*>(role.getParent());
                if (entity) {
                    xmltooling::auto_ptr_char name(entity->getEntityID());
                    setPeerName(name.get());
                }
            }
    
            virtual ~MetadataCredentialCriteria() {}
            
            /**
             * Return the metadata role associated with the credentials.
             *
             * @return the associated metadata role
             */
            const RoleDescriptor& getRole() const {
                return m_role;
            }

        private:
            const RoleDescriptor& m_role;
        };
    };
};

#endif /* __saml_metacred_h__ */