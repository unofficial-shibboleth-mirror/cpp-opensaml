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
 * WhitelistMetadataFilter.cpp
 *
 * Removes non-whitelisted entities from a metadata instance
 */

#include "internal.h"
#include "saml2/metadata/EntityMatcher.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"

#include <boost/bind.hpp>
#include <boost/scoped_ptr.hpp>
#include <xmltooling/logging.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace opensaml {
    namespace saml2md {
        class SAML_DLLLOCAL WhitelistMetadataFilter : public MetadataFilter
        {
        public:
            WhitelistMetadataFilter(const DOMElement* e, bool deprecationSupport=true);
            ~WhitelistMetadataFilter() {}

            const char* getId() const { return WHITELIST_METADATA_FILTER; }
            void doFilter(const MetadataFilterContext* ctx, XMLObject& xmlObject) const;

        private:
            void filterGroup(EntitiesDescriptor*) const;
            bool included(const EntityDescriptor&) const;

            set<xstring> m_entities;
            scoped_ptr<EntityMatcher> m_matcher;
        };

        MetadataFilter* SAML_DLLLOCAL WhitelistMetadataFilterFactory(const DOMElement* const & e, bool deprecationSupport)
        {
            return new WhitelistMetadataFilter(e);
        }

        static const XMLCh Include[] = UNICODE_LITERAL_7(I,n,c,l,u,d,e);
        static const XMLCh _matcher[] = UNICODE_LITERAL_7(m,a,t,c,h,e,r);
    };
};


WhitelistMetadataFilter::WhitelistMetadataFilter(const DOMElement* e, bool deprecationSupport)
{
    string matcher(XMLHelper::getAttrString(e, nullptr, _matcher));
    if (!matcher.empty())
        m_matcher.reset(SAMLConfig::getConfig().EntityMatcherManager.newPlugin(matcher.c_str(), e, deprecationSupport));

    e = XMLHelper::getFirstChildElement(e, Include);
    while (e) {
        if (e->hasChildNodes()) {
            const XMLCh* incl = e->getTextContent();
            if (incl && *incl)
                m_entities.insert(incl);
        }
        e = XMLHelper::getNextSiblingElement(e, Include);
    }
}

void WhitelistMetadataFilter::doFilter(const MetadataFilterContext* ctx, XMLObject& xmlObject) const
{
    EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(&xmlObject);
    if (group) {
        filterGroup(group);
    }
    else {
        EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(&xmlObject);
        if (entity) {
            if (!included(*entity))
                throw MetadataFilterException(WHITELIST_METADATA_FILTER " MetadataFilter instructed to filter the root/only entity in the metadata.");
        }
        else {
            throw MetadataFilterException(WHITELIST_METADATA_FILTER " MetadataFilter was given an improper metadata instance to filter.");
        }
    }
}

void WhitelistMetadataFilter::filterGroup(EntitiesDescriptor* entities) const
{
    Category& log = Category::getInstance(SAML_LOGCAT ".MetadataFilter." WHITELIST_METADATA_FILTER);

    VectorOf(EntityDescriptor) v = entities->getEntityDescriptors();
    for (VectorOf(EntityDescriptor)::size_type i = 0; i < v.size(); ) {
        if (!included(*v[i])) {
            auto_ptr_char id(v[i]->getEntityID());
            log.info("filtering out non-whitelisted entity (%s)", id.get());
            v.erase(v.begin() + i);
        }
        else {
            i++;
        }
    }

    const vector<EntitiesDescriptor*>& groups = const_cast<const EntitiesDescriptor*>(entities)->getEntitiesDescriptors();
    for_each(groups.begin(), groups.end(), boost::bind(&WhitelistMetadataFilter::filterGroup, this, _1));
}

bool WhitelistMetadataFilter::included(const EntityDescriptor& entity) const
{
    // Check for entityID.
    if (entity.getEntityID() && !m_entities.empty() && m_entities.count(entity.getEntityID()) > 0)
        return true;

    if (m_matcher && m_matcher->matches(entity))
        return true;

    return false;
}
