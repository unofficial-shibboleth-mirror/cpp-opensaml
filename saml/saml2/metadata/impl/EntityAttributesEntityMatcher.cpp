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
 * EntityAttributesEntityMatcher.cpp
 *
 * EntityMatcher that applies a set of input attributes.
 */

#include "internal.h"
#include "saml2/metadata/EntityMatcher.h"
#include "saml2/metadata/Metadata.h"

#include <boost/shared_ptr.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/casts.hpp>
#include <boost/lambda/lambda.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;

namespace opensaml {
    namespace saml2md {
        class SAML_DLLLOCAL EntityAttributesEntityMatcher : public EntityMatcher
        {
        public:
            EntityAttributesEntityMatcher(const DOMElement* e);
            ~EntityAttributesEntityMatcher() {}

            bool matches(const EntityDescriptor& entity) const;

        private:
            bool _matches(const EntityAttributes*, const Attribute*) const;

            bool m_trimTags;
            vector< boost::shared_ptr<Attribute> > m_tags;
        };

        EntityMatcher* SAML_DLLLOCAL EntityAttributesEntityMatcherFactory(const DOMElement* const & e)
        {
            return new EntityAttributesEntityMatcher(e);
        }

        static const XMLCh trimTags[] = UNICODE_LITERAL_8(t,r,i,m,T,a,g,s);
    };
};


EntityAttributesEntityMatcher::EntityAttributesEntityMatcher(const DOMElement* e)
    : m_trimTags(XMLHelper::getAttrBool(e, false, trimTags))
{
    DOMElement* child = XMLHelper::getFirstChildElement(e, samlconstants::SAML20_NS, Attribute::LOCAL_NAME);
    while (child) {
        boost::shared_ptr<XMLObject> obj(AttributeBuilder::buildOneFromElement(child));
        m_tags.push_back(boost::shared_dynamic_cast<Attribute>(obj));
        child = XMLHelper::getNextSiblingElement(child, samlconstants::SAML20_NS, Attribute::LOCAL_NAME);
    }

    if (m_tags.empty())
        throw XMLToolingException("EntityAttributes EntityMatcher requires at least one saml2:Attribute to match.");
}

bool EntityAttributesEntityMatcher::matches(const EntityDescriptor& entity) const
{
    // Check for a tag match in the EntityAttributes extension of the entity and its parent(s).
    const Extensions* exts = entity.getExtensions();
    if (exts) {
        const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
        const XMLObject* xo = find_if(children, ll_dynamic_cast<EntityAttributes*>(_1) != ((EntityAttributes*)nullptr));
        if (xo) {
            // If we find a matching tag, we win. Each tag is treated in OR fashion.
            if (find_if(m_tags.begin(), m_tags.end(),
                lambda::bind(&EntityAttributesEntityMatcher::_matches, this, dynamic_cast<const EntityAttributes*>(xo),
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
                    lambda::bind(&EntityAttributesEntityMatcher::_matches, this, dynamic_cast<const EntityAttributes*>(xo),
                        lambda::bind(&boost::shared_ptr<Attribute>::get, _1))) != m_tags.end()) {
                    return true;
                }
            }
        }
        group = dynamic_cast<EntitiesDescriptor*>(group->getParent());
    }

    return false;
}

bool EntityAttributesEntityMatcher::_matches(const EntityAttributes* ea, const Attribute* tag) const
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
