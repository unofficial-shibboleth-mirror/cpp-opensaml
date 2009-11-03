/*
 *  Copyright 2001-2009 Internet2
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

namespace xmltooling {
    class XMLTOOL_API RWLock;
};

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

            void init();
            xmltooling::Lockable* lock();
            void unlock();
            const xmltooling::XMLObject* getMetadata() const;
            std::pair<const EntityDescriptor*,const RoleDescriptor*> getEntityDescriptor(const Criteria& criteria) const;

        protected:
            /** Controls XML schema validation. */
            bool m_validate;

            /** Caps the allowable cache duration of a metadata instance. */
            time_t m_maxCacheDuration;

            using AbstractMetadataProvider::resolve;

            /**
             * Resolves a metadata instance using the supplied criteria.
             *
             * @param criteria  lookup criteria
             * @return  a valid metadata instance
             */
            virtual EntityDescriptor* resolve(const Criteria& criteria) const;

        private:
            mutable xmltooling::RWLock* m_lock;
        };

    };
};

#endif /* __saml2_dynmetadataprov_h__ */
