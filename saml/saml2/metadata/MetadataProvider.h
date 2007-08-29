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
 * @file saml/saml2/metadata/MetadataProvider.h
 * 
 * Supplies an individual source of metadata.
 */

#ifndef __saml2_metadataprov_h__
#define __saml2_metadataprov_h__

#include <saml/base.h>
#include <xmltooling/exceptions.h>
#include <xmltooling/XMLObject.h>
#include <xmltooling/security/CredentialResolver.h>

namespace opensaml {
    
    class SAML_API SAMLArtifact;

    namespace saml2md {

        class SAML_API EntityDescriptor;
        class SAML_API EntitiesDescriptor;
        class SAML_API RoleDescriptor;
        class SAML_API MetadataCredentialResolver;
        class SAML_API MetadataFilter;

#if defined (_MSC_VER)
        #pragma warning( push )
        #pragma warning( disable : 4251 )
#endif

        /**
         * Supplies an individual source of metadata.
         * 
         * The source can be a local file, remote service, or the result of a
         * dynamic lookup, can include local caching, etc. Providers
         * <strong>MUST</strong> be locked before any lookup operations.
         */
        class SAML_API MetadataProvider : public virtual xmltooling::CredentialResolver
        {
            MAKE_NONCOPYABLE(MetadataProvider);
        protected:
            /**
             * Constructor.
             * 
             * If a DOM is supplied, a set of default logic will be used to identify
             * and build MetadataFilter plugins and install them into the provider.
             * 
             * The following XML content is supported:
             * 
             * <ul>
             *  <li>&lt;MetadataFilter&gt; elements with a type attribute and type-specific content
             *  <li>&lt;Exclude&gt; elements representing a BlacklistMetadataFilter
             *  <li>&lt;BlacklistMetadataFilter&gt; element containing &lt;Exclude&gt; elements 
             *  <li>&lt;Include&gt; elements representing a WhitelistMetadataFilter
             *  <li>&lt;SignatureMetadataFilter&gt; element containing a &lt;KeyResolver&gt; element 
             *  <li>&lt;WhitelistMetadataFilter&gt; element containing &lt;Include&gt; elements 
             * </ul>
             * 
             * XML namespaces are ignored in the processing of these elements.
             * 
             * @param e DOM to supply configuration for provider
             */
            MetadataProvider(const xercesc::DOMElement* e=NULL);
            
        public:
            /**
             * Destructor will delete any installed filters.
             */
            virtual ~MetadataProvider();
            
            /**
             * Adds a metadata filter to apply to any resolved metadata. Will not be applied
             * to metadata that is already loaded.
             * 
             * @param newFilter metadata filter to add
             */
            virtual void addMetadataFilter(MetadataFilter* newFilter) {
                m_filters.push_back(newFilter);
            }

            /**
             * Removes a metadata filter. The caller must delete the filter if necessary.
             * 
             * @param oldFilter metadata filter to remove
             * @return  the old filter
             */
            virtual MetadataFilter* removeMetadataFilter(MetadataFilter* oldFilter) {
                for (std::vector<MetadataFilter*>::iterator i=m_filters.begin(); i!=m_filters.end(); i++) {
                    if (oldFilter==(*i)) {
                        m_filters.erase(i);
                        return oldFilter;
                    }
                }
                return NULL;
            }
            
            /**
             * Should be called after instantiating provider and adding filters, but before
             * performing any lookup operations. Allows the provider to defer initialization
             * processes that are likely to result in exceptions until after the provider is
             * safely created. Providers SHOULD perform as much processing as possible in
             * this method so as to report/log any errors that would affect later processing.
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
            virtual const EntityDescriptor* getEntityDescriptor(const XMLCh* id, bool requireValidMetadata=true) const;

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
             * Gets the metadata for an entity that issued a SAML artifact. If a valid entity is returned,
             * the provider will be left in a locked state. The caller MUST unlock the
             * provider when finished with the entity.
             *  
             * @param artifact              a SAML artifact to find the issuer of
             * 
             * @return the entity's metadata or NULL if there is no valid metadata
             */
            virtual const EntityDescriptor* getEntityDescriptor(const SAMLArtifact* artifact) const=0;

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
            virtual const EntitiesDescriptor* getEntitiesDescriptor(const XMLCh* name, bool requireValidMetadata=true) const;

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
            /**
             * Applies any installed filters to a metadata instance.
             * 
             * @param xmlObject the metadata to be filtered
             */
            void doFilters(xmltooling::XMLObject& xmlObject) const;

        private:
            std::vector<MetadataFilter*> m_filters;
        };

#if defined (_MSC_VER)
        #pragma warning( pop )
#endif

        /**
         * Registers MetadataProvider classes into the runtime.
         */
        void SAML_API registerMetadataProviders();
        
        /** MetadataProvider based on local or remote XML file */
        #define XML_METADATA_PROVIDER  "XML"

        /** MetadataProvider based on dynamic resolution */
        #define DYNAMIC_METADATA_PROVIDER  "Dynamic"

        /** MetadataProvider that wraps a sequence of metadata providers. */
        #define CHAINING_METADATA_PROVIDER  "Chaining"

        DECL_XMLTOOLING_EXCEPTION(MetadataException,SAML_EXCEPTIONAPI(SAML_API),opensaml::saml2md,xmltooling::XMLToolingException,Exceptions related to metadata use);
    };
};

#endif /* __saml2_metadataprov_h__ */
