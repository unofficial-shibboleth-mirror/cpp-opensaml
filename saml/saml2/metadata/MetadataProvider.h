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
 * @file MetadataProvider.h
 * 
 * Supplies an individual source of metadata.
 */

#ifndef __saml2_metadataprov_h__
#define __saml2_metadataprov_h__

#include <xmltooling/Lockable.h>
#include <saml/saml2/metadata/MetadataFilter.h>

namespace opensaml {

    namespace saml2md {
        
        /**
         * Supplies an individual source of metadata.
         * 
         * The source can be a local file, remote service, or the result of a
         * dynamic lookup, can include local caching, etc.
         */
        class SAML_API MetadataProvider : public virtual xmltooling::Lockable
        {
            MAKE_NONCOPYABLE(MetadataProvider);
        protected:
            MetadataProvider() : m_filter(NULL) {}
            
        public:
            virtual ~MetadataProvider() {
                delete m_filter;
            }
            
            /**
             * Gets the metadata filter applied to the resolved metadata.
             * 
             * @return the metadata filter applied to the resolved metadata
             */
            const MetadataFilter* getMetadataFilter() const {
                return m_filter;
            }
        
            /**
             * Sets the metadata filter applied to the resolved metadata.
             * 
             * @param newFilter the metadata filter applied to the resolved metadata
             */
            void setMetadataFilter(MetadataFilter* newFilter) {
                delete m_filter;
                m_filter=newFilter;
            }
            
            /**
             * Should be called after instantiating provider and setting filter, but before
             * performing any lookup operations. Allows the provider to defer initialization
             * processes that are likely to result in exceptions until after the provider is
             * safely created. Providers SHOULD perform as much processing as possible in
             * this method so as to report/log any errors that would affect later processing.
             * Also, any inputs supplied to the factory MUST persist until the completion of
             * this method, but the caller is then free to modify or delete them.
             */
            virtual void init()=0;
            
            /**
             * Gets the entire metadata tree, after the registered filter has been applied.
             * The caller MUST unlock the provider when finished with the data.
             * 
             * @return the entire metadata tree
             */
            virtual const xmltooling::XMLObject* getMetadata() const=0;
        
            /**
             * Gets the metadata for a given entity. If a valid entity is returned,
             * the provider will be left in a locked state. The caller MUST unlock the
             * provider when finished with the entity.
             *  
             * @param id                    the ID of the entity
             * @param requireValidMetadata  indicates whether the metadata for the entity must be valid/current
             * 
             * @return the entity's metadata or NULL if there is no metadata or no valid metadata
             */
            virtual const EntityDescriptor* getEntityDescriptor(const XMLCh* id, bool requireValidMetadata=true) const=0;

            /**
             * Gets the metadata for a given entity. If a valid entity is returned,
             * the provider will be left in a locked state. The caller MUST unlock the
             * provider when finished with the entity.
             *  
             * @param id                    the ID of the entity
             * @param requireValidMetadata  indicates whether the metadata for the entity must be valid/current
             * 
             * @return the entity's metadata or NULL if there is no metadata or no valid metadata
             */
            virtual const EntityDescriptor* getEntityDescriptor(const char* id, bool requireValidMetadata=true) const=0;

            /**
             * Gets the metadata for a given group of entities. If a valid group is returned,
             * the resolver will be left in a locked state. The caller MUST unlock the
             * resolver when finished with the group.
             * 
             * @param name                  the name of the group
             * @param requireValidMetadata  indicates whether the metadata for the group must be valid/current
             * 
             * @return the group's metadata or NULL if there is no metadata or no valid metadata
             */
            virtual const EntitiesDescriptor* getEntitiesDescriptor(const XMLCh* name, bool requireValidMetadata=true) const=0;

            /**
             * Gets the metadata for a given group of entities. If a valid group is returned,
             * the resolver will be left in a locked state. The caller MUST unlock the
             * resolver when finished with the group.
             * 
             * @param name                  the name of the group
             * @param requireValidMetadata  indicates whether the metadata for the group must be valid/current
             * 
             * @return the group's metadata or NULL if there is no metadata or no valid metadata
             */
            virtual const EntitiesDescriptor* getEntitiesDescriptor(const char* name, bool requireValidMetadata=true) const=0;

        protected:
            MetadataFilter* m_filter;
        };
        
        /**
         * Registers MetadataProvider classes into the runtime.
         */
        void SAML_API registerMetadataProviders();
        
        /** MetadataProvider based on local XML files */
        #define FILESYSTEM_METADATA_PROVIDER  "org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider"
    };
};

#endif /* __saml2_metadataprov_h__ */
