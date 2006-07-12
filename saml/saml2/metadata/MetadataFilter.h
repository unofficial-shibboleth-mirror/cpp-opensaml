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
 * @file MetadataFilter.h
 * 
 * Processes metadata after it's been unmarshalled.
 */

#ifndef __saml2_metadatafilt_h__
#define __saml2_metadatafilt_h__

#include <saml/saml2/metadata/Metadata.h>

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
             * @throws FilterException thrown if an error occurs during the filtering process
             */
            virtual void doFilter(xmltooling::XMLObject& xmlObject) const=0;
        };

    };
};

#endif /* __saml2_metadatafilt_h__ */
