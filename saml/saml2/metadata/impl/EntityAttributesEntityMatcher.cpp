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

#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/casts.hpp>
#include <boost/lambda/lambda.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling::logging;
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
            Category& m_log;
        };

        EntityMatcher* SAML_DLLLOCAL EntityAttributesEntityMatcherFactory(const DOMElement* const & e)
        {
            return new EntityAttributesEntityMatcher(e);
        }

        static const XMLCh attributeName[] =        UNICODE_LITERAL_13(a,t,t,r,i,b,u,t,e,N,a,m,e);
        static const XMLCh attributeNameFormat[] =  UNICODE_LITERAL_19(a,t,t,r,i,b,u,t,e,N,a,m,e,F,o,r,m,a,t);
        static const XMLCh attributeValue[] =       UNICODE_LITERAL_14(a,t,t,r,i,b,u,t,e,V,a,l,u,e);
        static const XMLCh attributeValueRegex[] =  UNICODE_LITERAL_19(a,t,t,r,i,b,u,t,e,V,a,l,u,e,R,e,g,e,x);
        static const XMLCh regex[] =                UNICODE_LITERAL_5(r,e,g,e,x);
        static const XMLCh trimTags[] =             UNICODE_LITERAL_8(t,r,i,m,T,a,g,s);
    };
};


EntityAttributesEntityMatcher::EntityAttributesEntityMatcher(const DOMElement* e)
    : m_trimTags(XMLHelper::getAttrBool(e, false, trimTags)),
        m_log(Category::getInstance(SAML_LOGCAT".EntityMatcher.EntityAttributes"))
{
    // Check for shorthand syntax.
    if (e && e->hasAttributeNS(nullptr, attributeName) && (e->hasAttributeNS(nullptr, attributeValue) || e->hasAttributeNS(nullptr, attributeValueRegex))) {
        boost::shared_ptr<Attribute> np(AttributeBuilder::buildAttribute());
        np->setName(e->getAttributeNS(nullptr, attributeName));
        np->setNameFormat(e->getAttributeNS(nullptr, attributeNameFormat));
        auto_ptr<AttributeValue> nval(AttributeValueBuilder::buildAttributeValue());
        if (e->hasAttributeNS(nullptr, attributeValue)) {
            nval->setTextContent(e->getAttributeNS(nullptr, attributeValue));
        }
        else {
            nval->setTextContent(e->getAttributeNS(nullptr, attributeValueRegex));
            // Use as a signal later that the value is a regex.
            nval->setAttribute(xmltooling::QName(nullptr, regex), xmlconstants::XML_ONE);
        }
        np->getAttributeValues().push_back(nval.get());
        nval.release();
        m_tags.push_back(np);
    }

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
    bool extFound = false;

    // Check for a tag match in the EntityAttributes extension of the entity and its parent(s).
    const Extensions* exts = entity.getExtensions();
    if (exts) {
        const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
        const XMLObject* xo = find_if(children, ll_dynamic_cast<EntityAttributes*>(_1) != ((EntityAttributes*)nullptr));
        if (xo) {
            extFound = true;
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
                extFound = true;
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

    if (!extFound && m_log.isDebugEnabled()) {
        auto_ptr_char id (entity.getEntityID());
        m_log.debug("no EntityAttributes extension found for (%s)", id.get());
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

        // Holds the active regex, if any.
        scoped_ptr<RegularExpression> re;
        xmltooling::QName regexQName(nullptr, regex);

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
                    re.reset();

                    // Check for a regex flag.
                    if (dynamic_cast<const AttributeExtensibleXMLObject*>(tagval)) {
                        const XMLCh* reflag = dynamic_cast<const AttributeExtensibleXMLObject*>(tagval)->getAttribute(regexQName);
                        if (reflag && (*reflag == chDigit_1 || *reflag == chLatin_t)) {
                            try {
                                re.reset(new RegularExpression(tagvalstr));
                            }
                            catch (XMLException& ex) {
                                auto_ptr_char msg(ex.getMessage());
                                m_log.error(msg.get());
                            }
                        }
                    }
                    
                    const vector<XMLObject*>& cvals = const_cast<const Attribute&>(*a).getAttributeValues();
                    for (indirect_iterator<vector<XMLObject*>::const_iterator> cval = make_indirect_iterator(cvals.begin());
                            cval != make_indirect_iterator(cvals.end()); ++cval) {
                        const XMLCh* cvalstr = cval->getDOM() ? cval->getDOM()->getTextContent() : cval->getTextContent();
                        if (tagvalstr && cvalstr) {
                            if (re) {
                                try {
                                    if (re->matches(cvalstr)) {
                                        flags[tagindex] = true;
                                        break;
                                    }
                                }
                                catch (XMLException& ex) {
                                    auto_ptr_char msg(ex.getMessage());
                                    m_log.error(msg.get());
                                }
                            }
                            else if (XMLString::equals(tagvalstr, cvalstr)) {
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
