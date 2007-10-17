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

#ifndef __saml_metacrit_h__
#define __saml_metacrit_h__

#include <saml/base.h>
#include <saml/saml2/metadata/MetadataCredentialContext.h>
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

            bool matches(const xmltooling::Credential& credential) const {
                const MetadataCredentialContext* context = dynamic_cast<const MetadataCredentialContext*>(credential.getCredentalContext());
                if (context) {
                    // Check for a usage mismatch.
                    if ((getUsage()==xmltooling::Credential::SIGNING_CREDENTIAL || getUsage()==xmltooling::Credential::TLS_CREDENTIAL) &&
                            XMLString::equals(context->getKeyDescriptor().getUse(),KeyDescriptor::KEYTYPE_ENCRYPTION))
                        return false;
                    else if (getUsage()==xmltooling::Credential::ENCRYPTION_CREDENTIAL &&
                            XMLString::equals(context->getKeyDescriptor().getUse(),KeyDescriptor::KEYTYPE_SIGNING))
                        return false;
                }
                return CredentialCriteria::matches(credential);
            }

        private:
            const RoleDescriptor& m_role;
        };
    };
};

#endif /* __saml_metacrit_h__ */
