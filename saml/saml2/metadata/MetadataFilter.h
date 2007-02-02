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
 * @file saml/saml2/metadata/MetadataFilter.h
 * 
 * Processes metadata after it's been unmarshalled.
 */

#include <saml/base.h>
#include <saml/exceptions.h>
#include <xmltooling/XMLObject.h>

#ifndef __saml2_metadatafilt_h__
#define __saml2_metadatafilt_h__

namespace opensaml {

    namespace saml2md {
        
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
            MetadataFilter() {}
        public:
            virtual ~MetadataFilter() {}
            
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
             * @param xmlObject the metadata to be filtered.
             */
            virtual void doFilter(xmltooling::XMLObject& xmlObject) const=0;
        };

        /**
         * Registers MetadataFilter classes into the runtime.
         */
        void SAML_API registerMetadataFilters();
        
        /** MetadataFilter that deletes blacklisted entities. */
        #define BLACKLIST_METADATA_FILTER  "org.opensaml.saml2.metadata.provider.BlacklistMetadataFilter"

        /** MetadataFilter that deletes all but whitelisted entities. */
        #define WHITELIST_METADATA_FILTER  "org.opensaml.saml2.metadata.provider.WhitelistMetadataFilter"

        /** MetadataFilter that verifies signatures and filters out any that don't pass. */
        #define SIGNATURE_METADATA_FILTER  "org.opensaml.saml2.metadata.provider.SignatureMetadataFilter"
        
        DECL_XMLTOOLING_EXCEPTION(MetadataException,SAML_EXCEPTIONAPI(SAML_API),opensaml::saml2md,xmltooling::XMLToolingException,Exceptions related to metadata use);
        DECL_XMLTOOLING_EXCEPTION(MetadataFilterException,SAML_EXCEPTIONAPI(SAML_API),opensaml::saml2md,MetadataException,Exceptions related to metadata filtering);
    };
};

#endif /* __saml2_metadatafilt_h__ */
