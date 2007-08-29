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
 * @file saml/saml2/metadata/DynamicMetadataProvider.h
 * 
 * Simple implementation of a dynamic caching MetadataProvider.
 */

#ifndef __saml2_dynmetadataprov_h__
#define __saml2_dynmetadataprov_h__

#include <saml/saml2/metadata/AbstractMetadataProvider.h>

namespace opensaml {
    namespace saml2md {

        /**
         * Simple implementation of a dynamic, caching MetadataProvider.
         */
        class SAML_API DynamicMetadataProvider : public AbstractMetadataProvider
        {
        public:
            /**
             * Constructor.
             * 
             * @param e DOM to supply configuration for provider
             */
            DynamicMetadataProvider(const xercesc::DOMElement* e=NULL);

            virtual ~DynamicMetadataProvider();

            xmltooling::Lockable* lock() {
                m_lock->rdlock();
                return this;
            }

            void unlock() {
                m_lock->unlock();
            }

            void init() {
            }

            const xmltooling::XMLObject* getMetadata() const {
                throw MetadataException("getMetadata operation not implemented on this provider.");
            }

            const EntityDescriptor* getEntityDescriptor(const char* id, bool requireValidMetadata=true) const;

        protected:
            /** Controls XML schema validation. */
            bool m_validate;

            /**
             * Resolves an entityID into a metadata instance for that entity.
             * 
             * @param entityID      entity ID to resolve
             * @return  a valid metadata instance
             */
            virtual EntityDescriptor* resolve(const char* entityID) const;

        private:
            mutable xmltooling::RWLock* m_lock;
        };
        
    };
};

#endif /* __saml2_dynmetadataprov_h__ */
