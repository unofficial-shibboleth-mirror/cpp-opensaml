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
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"

#include <boost/lambda/bind.hpp>
#include <boost/lambda/casts.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#include <xmltooling/logging.h>

using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;

namespace opensaml {
    namespace saml2md {
        class SAML_DLLLOCAL WhitelistMetadataFilter : public MetadataFilter
        {
        public:
            WhitelistMetadataFilter(const DOMElement* e);
            ~WhitelistMetadataFilter() {}

            const char* getId() const { return WHITELIST_METADATA_FILTER; }
            void doFilter(XMLObject& xmlObject) const;

        private:
            void filterGroup(EntitiesDescriptor&) const;
            bool included(const EntityDescriptor&) const;
            bool matches(const EntityAttributes*, const Attribute*) const;

            set<xstring> m_entities;
            bool m_trimTags;
            vector< boost::shared_ptr<Attribute> > m_tags;
        };

        MetadataFilter* SAML_DLLLOCAL WhitelistMetadataFilterFactory(const DOMElement* const & e)
        {
            return new WhitelistMetadataFilter(e);
        }

        static const XMLCh Include[] =  UNICODE_LITERAL_7(I,n,c,l,u,d,e);
        static const XMLCh trimTags[] = UNICODE_LITERAL_8(t,r,i,m,T,a,g,s);
    };
};


WhitelistMetadataFilter::WhitelistMetadataFilter(const DOMElement* e)
    : m_trimTags(XMLHelper::getAttrBool(e, false, trimTags))
{
    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        if (XMLString::equals(child->getLocalName(), Include) && child->hasChildNodes()) {
            m_entities.insert(child->getFirstChild()->getTextContent());
        }
        else if (XMLHelper::isNodeNamed(child, samlconstants::SAML20_NS, Attribute::LOCAL_NAME)) {
            boost::shared_ptr<XMLObject> obj(AttributeBuilder::buildOneFromElement(child));
            m_tags.push_back(boost::shared_dynamic_cast<Attribute>(obj));
        }
        child = XMLHelper::getNextSiblingElement(child);
    }
}

void WhitelistMetadataFilter::doFilter(XMLObject& xmlObject) const
{
    EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(&xmlObject);
    if (group) {
        filterGroup(*group);
    }
    else {
        EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(&xmlObject);
        if (entity) {
            if (!included(*entity))
                throw MetadataFilterException(WHITELIST_METADATA_FILTER" MetadataFilter instructed to filter the root/only entity in the metadata.");
        }
        else {
            throw MetadataFilterException(WHITELIST_METADATA_FILTER" MetadataFilter was given an improper metadata instance to filter.");
        }
    }
}

void WhitelistMetadataFilter::filterGroup(EntitiesDescriptor& entities) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".MetadataFilter."WHITELIST_METADATA_FILTER);

    VectorOf(EntityDescriptor) v = entities.getEntityDescriptors();
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

    const vector<EntitiesDescriptor*>& groups = const_cast<const EntitiesDescriptor&>(entities).getEntitiesDescriptors();
    for_each(
        make_indirect_iterator(groups.begin()), make_indirect_iterator(groups.end()),
        lambda::bind(&WhitelistMetadataFilter::filterGroup, this, _1)
        );
}

bool WhitelistMetadataFilter::included(const EntityDescriptor& entity) const
{
    // Check for entityID.
    if (entity.getEntityID() && !m_entities.empty() && m_entities.count(entity.getEntityID()) == 1)
        return true;

    // Check for a tag match in the EntityAttributes extension of the entity and its parent(s).
    if (!m_tags.empty()) {
        const Extensions* exts = entity.getExtensions();
        if (exts) {
            const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
            const XMLObject* xo = find_if(children, ll_dynamic_cast<EntityAttributes*>(_1) != ((EntityAttributes*)nullptr));
            if (xo) {
                // If we find a matching tag, we win. Each tag is treated in OR fashion.
                if (find_if(m_tags.begin(), m_tags.end(),
                    lambda::bind(&WhitelistMetadataFilter::matches, this, dynamic_cast<const EntityAttributes*>(xo),
                        lambda::bind(&boost::shared_ptr<Attribute>::get, _1))) != m_tags.end()) {
                    return true;
                }
            }
        }

        const EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(entity.getParent());
        while (group) {
            exts = group->getExtensions();
            if (exts) {
                const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
                const XMLObject* xo = find_if(children, ll_dynamic_cast<EntityAttributes*>(_1) != ((EntityAttributes*)nullptr));
                if (xo) {
                    // If we find a matching tag, we win. Each tag is treated in OR fashion.
                    if (find_if(m_tags.begin(), m_tags.end(),
                        lambda::bind(&WhitelistMetadataFilter::matches, this, dynamic_cast<const EntityAttributes*>(xo),
                            lambda::bind(&boost::shared_ptr<Attribute>::get, _1))) != m_tags.end()) {
                        return true;
                    }
                }
            }
            group = dynamic_cast<EntitiesDescriptor*>(group->getParent());
        }
    }
    return false;
}

bool WhitelistMetadataFilter::matches(const EntityAttributes* ea, const Attribute* tag) const
{
    const vector<Attribute*>& attrs = ea->getAttributes();
    const vector<XMLObject*>& tagvals = tag->getAttributeValues();
    if (!attrs.empty() && !tagvals.empty()) {
        // Track whether we've found every tag value.
        vector<bool> flags(tagvals.size());

        // Check each attribute/tag in the candidate.
        for (indirect_iterator<vector<Attribute*>::const_iterator> a = make_indirect_iterator(attrs.begin());
                a != make_indirect_iterator(attrs.end()); ++a) {
            // Compare Name and NameFormat for a matching tag.
            if (XMLString::equals(a->getName(), tag->getName()) &&
                (!tag->getNameFormat() || XMLString::equals(tag->getNameFormat(), Attribute::UNSPECIFIED) ||
                    XMLString::equals(tag->getNameFormat(), a->getNameFormat()))) {
                // Check each tag value's simple content for a match.
                for (vector<XMLObject*>::size_type tagindex = 0; tagindex < tagvals.size(); ++tagindex) {
                    const XMLObject* tagval = tagvals[tagindex];
                    const XMLCh* tagvalstr = (tagval->getDOM()) ? tagval->getDOM()->getTextContent() : tagval->getTextContent();
                    const vector<XMLObject*>& cvals = const_cast<const Attribute&>(*a).getAttributeValues();
                    for (indirect_iterator<vector<XMLObject*>::const_iterator> cval = make_indirect_iterator(cvals.begin());
                            cval != make_indirect_iterator(cvals.end()); ++cval) {
                        const XMLCh* cvalstr = cval->getDOM() ? cval->getDOM()->getTextContent() : cval->getTextContent();
                        if (tagvalstr && cvalstr) {
                            if (XMLString::equals(tagvalstr, cvalstr)) {
                                flags[tagindex] = true;
                                break;
                            }
                            else if (m_trimTags) {
                                XMLCh* dup = XMLString::replicate(cvalstr);
                                XMLString::trim(dup);
                                if (XMLString::equals(tagvalstr, dup)) {
                                    XMLString::release(&dup);
                                    flags[tagindex] = true;
                                    break;
                                }
                                XMLString::release(&dup);
                            }
                        }
                    }
                }
            }
        }

        if (find(flags.begin(), flags.end(), false) == flags.end())
            return true;
    }
    return false;
}
