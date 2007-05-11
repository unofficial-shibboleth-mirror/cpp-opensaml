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
 * @file saml/saml2/metadata/AbstractMetadataProvider.h
 * 
 * Base class for caching metadata providers.
 */

#ifndef __saml2_absmetadataprov_h__
#define __saml2_absmetadataprov_h__

#include <saml/saml2/metadata/ObservableMetadataProvider.h>

#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/util/Threads.h>

namespace opensaml {
    namespace saml2md {
        
        class SAML_API MetadataFilter;

        /**
         * Base class for caching metadata providers.
         */
        class SAML_API AbstractMetadataProvider : public ObservableMetadataProvider
        {
        protected:
            /**
             * Constructor.
             * 
             * If a DOM is supplied, a set of default logic will be used to identify
             * and build a KeyInfoResolver plugin and install it into the provider.
             * 
             * The following XML content is supported:
             * 
             * <ul>
             *  <li>&lt;KeyInfoResolver&gt; elements with a type attribute
             * </ul>
             * 
             * XML namespaces are ignored in the processing of these elements.
             * 
             * @param e DOM to supply configuration for provider
             */
            AbstractMetadataProvider(const xercesc::DOMElement* e=NULL);
            
        public:
            virtual ~AbstractMetadataProvider();
            
            using MetadataProvider::getEntityDescriptor;
            using MetadataProvider::getEntitiesDescriptor;

            void emitChangeEvent() const;
            const EntityDescriptor* getEntityDescriptor(const char* id, bool requireValidMetadata=true) const;
            const EntityDescriptor* getEntityDescriptor(const SAMLArtifact* artifact) const;
            const EntitiesDescriptor* getEntitiesDescriptor(const char* name, bool requireValidMetadata=true) const;
            const xmltooling::Credential* resolve(const xmltooling::CredentialCriteria* criteria=NULL) const;
            std::vector<const xmltooling::Credential*>::size_type resolve(
                std::vector<const xmltooling::Credential*>& results, const xmltooling::CredentialCriteria* criteria=NULL
                ) const;

        protected:
            /** Embedded KeyInfoResolver instance. */
            xmltooling::KeyInfoResolver* m_resolver;

            /**
             * Loads an entity into the cache for faster lookup. This includes
             * processing known reverse lookup strategies for artifacts.
             * 
             * @param site          entity definition
             * @param validUntil    expiration time of the entity definition
             */
            virtual void index(EntityDescriptor* site, time_t validUntil);

            /**
             * Loads a group of entities into the cache for faster lookup.
             * 
             * @param group         group definition
             * @param validUntil    expiration time of the group definition
             */
            virtual void index(EntitiesDescriptor* group, time_t validUntil);
        
            /**
             * Clear the cache of known entities and groups.
             */
            virtual void clearDescriptorIndex();

        private:
            typedef std::multimap<std::string,const EntityDescriptor*> sitemap_t;
            typedef std::multimap<std::string,const EntitiesDescriptor*> groupmap_t;
            sitemap_t m_sites;
            sitemap_t m_sources;
            groupmap_t m_groups;

            mutable xmltooling::Mutex* m_credentialLock;
            typedef std::map< const RoleDescriptor*, std::vector<xmltooling::Credential*> > credmap_t;
            mutable credmap_t m_credentialMap;
            const credmap_t::mapped_type& resolveCredentials(const RoleDescriptor& role) const;
        };
        
    };
};

#endif /* __saml2_absmetadataprov_h__ */
