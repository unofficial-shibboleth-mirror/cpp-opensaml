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
 * @file saml/saml2/metadata/MetadataFilter.h
 *
 * Processes metadata after it's been unmarshalled.
 */

#include <saml/saml2/metadata/MetadataProvider.h>

#ifndef __saml2_metadatafilt_h__
#define __saml2_metadatafilt_h__

namespace opensaml {
    namespace saml2md {

        /**
         * Marker interface for supplying environmental context to filters.
         */
        class SAML_API MetadataFilterContext
        {
            MAKE_NONCOPYABLE(MetadataFilterContext);
        protected:
            MetadataFilterContext();
        public:
            virtual ~MetadataFilterContext();
        };

        /**
         * Environmental context for filtering of batch-loaded metadata.
         */
        class SAML_API BatchLoadMetadataFilterContext : public virtual MetadataFilterContext
        {
            MAKE_NONCOPYABLE( BatchLoadMetadataFilterContext);
        public:
            /**
             * Constructor.
             *
             * @param isBackingFile initial setting for backing file flag
             */
            BatchLoadMetadataFilterContext(bool isBackingFile);
            virtual ~BatchLoadMetadataFilterContext();

            /**
             * Get whether the filtering is over a backing copy of the metadata.
             *
             * @return true iff the filtering operation is over a backing copy
             */
            bool isBackingFile() const;

            /**
            * Set whether the filtering is over a backing copy of the metadata.
            *
            * @param flag flag to set
            */
            void setBackingFile(bool flag);

        private:
            bool m_isBackingFile;
        };

        /**
         * A metadata filter is used to process metadata after resolution and unmarshalling.
         *
         * Some filters might remove everything but identity provider roles, decreasing the data a service provider
         * needs to work with, or a filter could be used to perform integrity checking on the retrieved metadata by
         * verifying a digital signature.
         */
        class SAML_API MetadataFilter
        {
            MAKE_NONCOPYABLE(MetadataFilter);
        protected:
            MetadataFilter();
        public:
            virtual ~MetadataFilter();

            /**
             * Returns an identifying string for the filter.
             *
             * @return the ID string
             */
            virtual const char* getId() const=0;

            /**
             * Filters the given metadata. Exceptions should generally not be thrown to
             * signal the removal of information, only for systemic processing failure.
             *
             * @param ctx       context interface, or nullptr
             * @param xmlObject the metadata to be filtered
             */
            virtual void doFilter(const MetadataFilterContext* ctx, xmltooling::XMLObject& xmlObject) const=0;
        };

        /**
         * Registers MetadataFilter classes into the runtime.
         */
        void SAML_API registerMetadataFilters();

        /** MetadataFilter that deletes blacklisted entities. */
        #define BLACKLIST_METADATA_FILTER           "Blacklist"

        /** MetadataFilter that deletes all but whitelisted entities. */
        #define WHITELIST_METADATA_FILTER           "Whitelist"

        /** MetadataFilter that verifies signatures and filters out any that don't pass. */
        #define SIGNATURE_METADATA_FILTER           "Signature"

        /** MetadataFilter that enforces expiration requirements. */
        #define REQUIREVALIDUNTIL_METADATA_FILTER   "RequireValidUntil"

        /** MetadataFilter that removes non-retained roles. */
        #define ENTITYROLE_METADATA_FILTER          "EntityRoleWhiteList"

        /** MetadataFilter that adds EntityAttributes extension. */
        #define ENTITYATTR_METADATA_FILTER          "EntityAttributes"

        DECL_XMLTOOLING_EXCEPTION(MetadataFilterException,SAML_EXCEPTIONAPI(SAML_API),opensaml::saml2md,MetadataException,Exceptions related to metadata filtering);
    };
};

#endif /* __saml2_metadatafilt_h__ */
