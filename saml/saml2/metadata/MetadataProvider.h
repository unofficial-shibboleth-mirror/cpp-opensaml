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
 * @file saml/saml2/metadata/MetadataProvider.h
 *
 * Supplies an individual source of metadata.
 */

#ifndef __saml2_metadataprov_h__
#define __saml2_metadataprov_h__

#include <saml/base.h>

#include <vector>
#include <iostream>
#include <boost/ptr_container/ptr_vector.hpp>
#include <xmltooling/exceptions.h>
#include <xmltooling/security/CredentialResolver.h>

namespace xmltooling {
    class XMLTOOL_API QName;
    class XMLTOOL_API XMLObject;
};

namespace opensaml {

    class SAML_API SAMLArtifact;

    namespace saml2md {

        class SAML_API EntityDescriptor;
        class SAML_API EntitiesDescriptor;
        class SAML_API RoleDescriptor;
        class SAML_API MetadataCredentialResolver;
        class SAML_API MetadataFilter;
        class SAML_API MetadataFilterContext;

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
            MetadataProvider(const xercesc::DOMElement* e=nullptr);

        public:
            /**
             * Destructor will delete any installed filters.
             */
            virtual ~MetadataProvider();

            /**
             * Returns an identifier for the provider for logging/status purposes.
             *
             * @return an identifier, or null
             */
            virtual const char* getId() const;

            /**
             * Adds a metadata filter to apply to any resolved metadata. Will not be applied
             * to metadata that is already loaded.
             *
             * @param newFilter metadata filter to add
             */
            virtual void addMetadataFilter(MetadataFilter* newFilter);

            /**
             * Removes a metadata filter. The caller must delete the filter if necessary.
             *
             * @param oldFilter metadata filter to remove
             * @return  the old filter
             */
            virtual MetadataFilter* removeMetadataFilter(MetadataFilter* oldFilter);

            /**
             * Sets a filtering context object for use by the filtering process.
             * <p>The object's lifetime must last for the duration of the lifetime
             * of the MetadataProvider.
             *
             * @param ctx   a context object
             */
            void setContext(const MetadataFilterContext* ctx);

            /**
             * Should be called after instantiating provider and adding filters, but before
             * performing any lookup operations. Allows the provider to defer initialization
             * processes that are likely to result in exceptions until after the provider is
             * safely created. Providers SHOULD perform as much processing as possible in
             * this method so as to report/log any errors that would affect later processing.
             */
            virtual void init()=0;

            /**
             * Generate an XML representation of the provider's status. The XML must be
             * well-formed, but is otherwise arbitrary.
             *
             * @param os    stream to write status information to
             */
            virtual void outputStatus(std::ostream& os) const;

            /**
             * Gets the entire metadata tree, after the registered filter has been applied.
             * The caller MUST unlock the provider when finished with the data.
             *
             * @return the entire metadata tree
             */
            virtual const xmltooling::XMLObject* getMetadata() const=0;

            /**
             * Gets the metadata for a given group of entities. If a valid group is returned,
             * the resolver will be left in a locked state. The caller MUST unlock the
             * resolver when finished with the group.
             *
             * @param name                  the name of the group
             * @param requireValidMetadata  indicates whether the metadata for the group must be valid/current
             *
             * @return the group's metadata or nullptr if there is no metadata or no valid metadata
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
             * @return the group's metadata or nullptr if there is no metadata or no valid metadata
             */
            virtual const EntitiesDescriptor* getEntitiesDescriptor(const char* name, bool requireValidMetadata=true) const=0;

            /**
             * Batches up criteria for entity lookup.
             */
            struct SAML_API Criteria {
                /**
                 * Default constructor.
                 */
                Criteria();

                /**
                 * Constructor.
                 *
                 * @param id    entityID to lookup
                 * @param q     element/type of role, if any
                 * @param prot  protocol support constant, if any
                 * @param valid true iff stale metadata should be ignored
                 */
                Criteria(const XMLCh* id, const xmltooling::QName* q=nullptr, const XMLCh* prot=nullptr, bool valid=true);

                /**
                 * Constructor.
                 *
                 * @param id    entityID to lookup
                 * @param q     element/type of role, if any
                 * @param prot  protocol support constant, if any
                 * @param valid true iff stale metadata should be ignored
                 */
                Criteria(const char* id, const xmltooling::QName* q=nullptr, const XMLCh* prot=nullptr, bool valid=true);

                /**
                 * Constructor.
                 *
                 * @param a     artifact to lookup
                 * @param q     element/type of role, if any
                 * @param prot  protocol support constant, if any
                 * @param valid true iff stale metadata should be ignored
                 */
                Criteria(const SAMLArtifact* a, const xmltooling::QName* q=nullptr, const XMLCh* prot=nullptr, bool valid=true);

                virtual ~Criteria();

                /**
                 * Restores the object to its default state.
                 */
                virtual void reset();

                /** Unique ID of entity. */
                const XMLCh* entityID_unicode;
                /** Unique ID of entity. */
                const char* entityID_ascii;
                /** SAML artifact */
                const SAMLArtifact* artifact;
                /** Element or schema type QName of metadata role. */
                const xmltooling::QName* role;
                /** Protocol support constant. */
                const XMLCh* protocol;
                /** Backup protocol support constant. */
                const XMLCh* protocol2;
                /** Controls whether stale metadata is ignored. */
                bool validOnly;
            };

            /**
             * Gets entity metadata based on supplied criteria. If a valid entity is returned,
             * the provider will be left in a locked state. The caller MUST unlock the
             * provider when finished with the entity.
             *
             * @param criteria  lookup criteria
             *
             * @return the entity's metadata (and optionally a role) or nullptr if there is no qualifying metadata
             */
            virtual std::pair<const EntityDescriptor*,const RoleDescriptor*> getEntityDescriptor(const Criteria& criteria) const=0;

        protected:
            /**
             * @Deprecated
             * Applies any installed filters to a metadata instance.
             * This passes the statically provided context to the filter
             * and so is equivalent to doFilters(m_filterContext, xmlObject)
             *
             * @param xmlObject the metadata to be filtered
             */
            void doFilters(xmltooling::XMLObject& xmlObject) const;

            /**
             * Applies any installed filters to a metadata instance.
             * This must not be called if the static context has been set (via setContext).
             *
             * @param ctx The Context for this filtering operation.
             * @param xmlObject the metadata to be filtered
             */
            void doFilters(const MetadataFilterContext* ctx, xmltooling::XMLObject& xmlObject) const;

        private:
            void doFiltersInternal(const MetadataFilterContext* ctx, xmltooling::XMLObject& xmlObject) const;
            const MetadataFilterContext* m_filterContext;
            boost::ptr_vector<MetadataFilter> m_filters;
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

        /** MetadataProvider based on dynamic resolution from a URL. */
        #define DYNAMIC_METADATA_PROVIDER  "Dynamic"

        /** MetadataProvider based on dynamic resolution from a file system.  */
        #define LOCAL_DYNAMIC_METADATA_PROVIDER  "LocalDynamic"

        /** MetadataProvider based on dynamic resolution from an MDQ server. */
        #define MDQ_METADATA_PROVIDER  "MDQ"

        /** MetadataProvider that wraps a sequence of metadata providers. */
        #define CHAINING_METADATA_PROVIDER  "Chaining"

        /** MetadataProvider that loads a directory of files. */
        #define FOLDER_METADATA_PROVIDER  "Folder"

        /** MetadataProvider that returns an empty "dummy" entity descriptor. */
        #define NULL_METADATA_PROVIDER  "Null"

        DECL_XMLTOOLING_EXCEPTION(MetadataException,SAML_EXCEPTIONAPI(SAML_API),opensaml::saml2md,xmltooling::XMLToolingException,Exceptions related to metadata use);
    };
};

#endif /* __saml2_metadataprov_h__ */
