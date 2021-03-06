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
 * EntityAttributesMetadataFilter.cpp
 *
 * Adds EntityAttributes tags to entities.
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

#include <xercesc/util/regx/RegularExpression.hpp>

using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;

namespace opensaml {
    namespace saml2md {

        class SAML_DLLLOCAL EntityAttributesMetadataFilter : public MetadataFilter
        {
        public:
            EntityAttributesMetadataFilter(const DOMElement* e);
            ~EntityAttributesMetadataFilter() {}

            const char* getId() const { return ENTITYATTR_METADATA_FILTER; }
            void doFilter(const MetadataFilterContext* ctx, XMLObject& xmlObject) const;

        private:
            void filterEntity(EntityDescriptor* entity) const;
            void filterGroup(EntitiesDescriptor* entities) const;
            EntityAttributes* getEntityAttributes(EntityDescriptor* entity) const;

            Category& m_log;
            vector< boost::shared_ptr<Attribute> > m_attributes;
            typedef multimap<xstring,const Attribute*> applymap_t;
            typedef map< boost::shared_ptr<RegularExpression>,vector<const Attribute*> > regexmap_t;
            applymap_t m_applyMap;
            regexmap_t m_regexMap;
        };

        MetadataFilter* SAML_DLLLOCAL EntityAttributesMetadataFilterFactory(const DOMElement* const & e, bool)
        {
            return new EntityAttributesMetadataFilter(e);
        }

        static const XMLCh Entity[] =       UNICODE_LITERAL_6(E,n,t,i,t,y);
        static const XMLCh EntityRegex[] =  UNICODE_LITERAL_11(E,n,t,i,t,y,R,e,g,e,x);

    };
};


EntityAttributesMetadataFilter::EntityAttributesMetadataFilter(const DOMElement* e)
    : m_log(Category::getInstance(SAML_LOGCAT".MetadataFilter.EntityAttributes"))
{
    // Contains ordered set of Attribute and Entity elements.
    // We track each Attribute we find, and then consume an Entity by adding.
    // a mapping from the Entity to every Attribute seen to that point.
    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        if (XMLHelper::isNodeNamed(child, samlconstants::SAML20_NS, Attribute::LOCAL_NAME)) {
            boost::shared_ptr<XMLObject> obj(AttributeBuilder::buildOneFromElement(child));
            m_attributes.push_back(boost::dynamic_pointer_cast<Attribute>(obj));
        }
        else if (XMLString::equals(child->getLocalName(), Entity)) {
            const XMLCh* eid = XMLHelper::getTextContent(child);
            if (eid && *eid) {
                for (vector< boost::shared_ptr<Attribute> >::const_iterator a = m_attributes.begin(); a != m_attributes.end(); ++a)
                    m_applyMap.insert(applymap_t::value_type(eid, a->get()));
            }
        }
        else if (XMLString::equals(child->getLocalName(), EntityRegex)) {
            const XMLCh* exp = XMLHelper::getTextContent(child);
            if (exp && *exp) {
                boost::shared_ptr<RegularExpression> regexp;
                try {
                    regexp.reset(new RegularExpression(exp));
                    vector<const Attribute*>& tags = m_regexMap[regexp];
                    for (vector< boost::shared_ptr<Attribute> >::const_iterator a = m_attributes.begin(); a != m_attributes.end(); ++a)
                        tags.push_back(a->get());
                }
                catch (XMLException& ex) {
                    auto_ptr_char msg(ex.getMessage());
                    m_log.error(msg.get());
                }
            }
        }
        child = XMLHelper::getNextSiblingElement(child);
    }
}

void EntityAttributesMetadataFilter::doFilter(const MetadataFilterContext*, XMLObject& xmlObject) const
{
    EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(&xmlObject);
    if (group) {
        filterGroup(group);
    }
    else {
        EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(&xmlObject);
        if (entity) {
            filterEntity(entity);
        }
        else {
            throw MetadataFilterException(ENTITYATTR_METADATA_FILTER " MetadataFilter was given an improper metadata instance to filter.");
        }
    }
}

void EntityAttributesMetadataFilter::filterGroup(EntitiesDescriptor* entities) const
{
    const vector<EntityDescriptor*>& v = const_cast<const EntitiesDescriptor*>(entities)->getEntityDescriptors();
    for_each(v.begin(), v.end(), lambda::bind(&EntityAttributesMetadataFilter::filterEntity, this, _1));

    const vector<EntitiesDescriptor*>& v2 = const_cast<const EntitiesDescriptor*>(entities)->getEntitiesDescriptors();
    for_each(v2.begin(), v2.end(), lambda::bind(&EntityAttributesMetadataFilter::filterGroup, this, _1));
}

void EntityAttributesMetadataFilter::filterEntity(EntityDescriptor* entity) const
{
    if (!entity->getEntityID())
        return;
    
    pair<applymap_t::const_iterator,applymap_t::const_iterator> tags = m_applyMap.equal_range(entity->getEntityID());
    if (tags.first != tags.second) {
        EntityAttributes* wrapper = getEntityAttributes(entity);
        VectorOf(Attribute) attrs = wrapper->getAttributes();
        for (; tags.first != tags.second; ++tags.first) {
            auto_ptr<Attribute> np(tags.first->second->cloneAttribute());
            attrs.push_back(np.get());
            np.release();
        }
    }

    for (regexmap_t::const_iterator i = m_regexMap.begin(); i != m_regexMap.end(); ++i) {
        try {
            if (i->first->matches(entity->getEntityID())) {
                EntityAttributes* wrapper = getEntityAttributes(entity);
                VectorOf(Attribute) attrs = wrapper->getAttributes();
                for (vector<const Attribute*>::const_iterator a = i->second.begin(); a != i->second.end(); ++a) {
                    auto_ptr<Attribute> np((*a)->cloneAttribute());
                    attrs.push_back(np.get());
                    np.release();
                }
            }
        }
        catch (const XMLException& ex) {
            auto_ptr_char msg(ex.getMessage());
            m_log.error(msg.get());
        }
    }
}

EntityAttributes* EntityAttributesMetadataFilter::getEntityAttributes(EntityDescriptor* entity) const
{
    Extensions* exts = entity->getExtensions();
    if (!exts) {
        entity->setExtensions(ExtensionsBuilder::buildExtensions());
        exts = entity->getExtensions();
    }
    EntityAttributes* wrapper = nullptr;
    const vector<XMLObject*>& children = const_cast<const Extensions*>(exts)->getUnknownXMLObjects();
    XMLObject* xo = find_if(children, ll_dynamic_cast<EntityAttributes*>(_1) != ((EntityAttributes*)nullptr));
    if (xo) {
        wrapper = dynamic_cast<EntityAttributes*>(xo);
    }
    else {
        wrapper = EntityAttributesBuilder::buildEntityAttributes();
        exts->getUnknownXMLObjects().push_back(wrapper);
    }

    return wrapper;
}
