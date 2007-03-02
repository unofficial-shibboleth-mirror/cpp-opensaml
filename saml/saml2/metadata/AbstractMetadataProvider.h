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

namespace opensaml {

    namespace saml2md {
        
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
             * and build a KeyResolver plugin and install it into the provider.
             * 
             * The following XML content is supported:
             * 
             * <ul>
             *  <li>&lt;KeyResolver&gt; elements with a type attribute
             * </ul>
             * 
             * XML namespaces are ignored in the processing of these elements.
             * 
             * @param e DOM to supply configuration for provider
             */
            AbstractMetadataProvider(const DOMElement* e=NULL);
            
            void emitChangeEvent();
            
        public:
            virtual ~AbstractMetadataProvider();
            
            virtual const xmltooling::KeyResolver* getKeyResolver() const {
                return m_resolver;
            }
            
            virtual const EntityDescriptor* getEntityDescriptor(const char* id, bool requireValidMetadata=true) const;
            virtual const EntityDescriptor* getEntityDescriptor(const SAMLArtifact* artifact) const;
            virtual const EntitiesDescriptor* getEntitiesDescriptor(const char* name, bool requireValidMetadata=true) const;

        protected:
            /** Embedded KeyResolver instance. */
            xmltooling::KeyResolver* m_resolver;

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
            std::vector<MetadataFilter*> m_filters;

            typedef std::multimap<std::string,const EntityDescriptor*> sitemap_t;
            typedef std::multimap<std::string,const EntitiesDescriptor*> groupmap_t;
            sitemap_t m_sites;
            sitemap_t m_sources;
            groupmap_t m_groups;
        };
        
    };
};

#endif /* __saml2_absmetadataprov_h__ */
