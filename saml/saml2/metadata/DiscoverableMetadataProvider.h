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
 * @file saml/saml2/metadata/DiscoverableMetadataProvider.h
 * 
 * A metadata provider that provides a JSON feed of IdP discovery information.
 */

#ifndef __saml2_discometadataprov_h__
#define __saml2_discometadataprov_h__

#include <saml/saml2/metadata/MetadataProvider.h>

namespace opensaml {
    
    namespace saml2md {
        
#if defined (_MSC_VER)
        #pragma warning( push )
        #pragma warning( disable : 4251 )
#endif
        /**
         * A metadata provider that provides a JSON feed of IdP discovery information.
         */
        class SAML_API DiscoverableMetadataProvider : public virtual MetadataProvider
        {
        protected:
            /**
             * Constructor.
             *
             * If a DOM is supplied, the following XML content is supported:
             *
             * <dl>
             *   <dt>legacyOrgNames</dt>
             *   <dd>true iff IdPs without a UIInfo extension should
             *      be identified using &lt;md:OrganizationDisplayName&gt;</dd>
             * </dl>
             *
             * @param e DOM to supply configuration for provider
             */
            DiscoverableMetadataProvider(const xercesc::DOMElement* e=nullptr);
            
            /**
             * Generates a JSON feed of IdP discovery information for the current metadata.
             * <p>The provider <strong>MUST</strong> be write-locked.
             */
            virtual void generateFeed();

        public:
            virtual ~DiscoverableMetadataProvider();

            /**
             * Returns the ETag associated with the cached feed.
             * <p>The provider <strong>MUST</strong> be locked.
             *
             * @return the ETag value for the current feed state
             */
            virtual std::string getCacheTag() const;

            /**
             * Outputs the cached feed.
             * <p>The provider <strong>MUST</strong> be locked.
             *
             * @param os        stream to output feed into
             * @param first     on input, indicates if the feed is first in position,
             *                  on output will be false if the feed was non-empty
             * @param wrapArray true iff the feed array should be opened/closed by this provider
             */
            virtual void outputFeed(std::ostream& os, bool& first, bool wrapArray=true) const;

        protected:
            /** Storage for feed. */
            std::string m_feed;

            /** ETag for feed. */
            mutable std::string m_feedTag;

        private:
            void disco(std::string& s, const EntityDescriptor* entity, bool& first) const;
            void disco(std::string& s, const EntitiesDescriptor* group, bool& first) const;

            bool m_legacyOrgNames;
        };

#if defined (_MSC_VER)
        #pragma warning( pop )
#endif

    };
};

#endif /* __saml2_discometadataprov_h__ */
