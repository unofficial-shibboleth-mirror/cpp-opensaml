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
 * UIInfoMetadataFilter.cpp
 *
 * Adds UIInfo extension to entities.
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

        class SAML_DLLLOCAL UIInfoMetadataFilter : public MetadataFilter
        {
        public:
            UIInfoMetadataFilter(const DOMElement* e);
            ~UIInfoMetadataFilter() {}

            const char* getId() const { return UIINFO_METADATA_FILTER; }
            void doFilter(const MetadataFilterContext* ctx, XMLObject& xmlObject) const;

        private:
            void filterEntity(EntityDescriptor* entity) const;
            void filterGroup(EntitiesDescriptor* entities) const;
            Extensions* getContainer(IDPSSODescriptor* entity) const;

            Category& m_log;
            bool m_replace;
            vector< boost::shared_ptr<UIInfo> > m_infos;
            typedef map<xstring,const UIInfo*> applymap_t;
            applymap_t m_applyMap;
        };

        MetadataFilter* SAML_DLLLOCAL UIInfoMetadataFilterFactory(const DOMElement* const & e, bool)
        {
            return new UIInfoMetadataFilter(e);
        }

        static const XMLCh Entity[] =       UNICODE_LITERAL_6(E,n,t,i,t,y);
        static const XMLCh replace[] =      UNICODE_LITERAL_7(r,e,p,l,a,c,e);
    };
};


UIInfoMetadataFilter::UIInfoMetadataFilter(const DOMElement* e)
    : m_log(Category::getInstance(SAML_LOGCAT".MetadataFilter.UIInfo")),
        m_replace(XMLHelper::getAttrBool(e, false, replace))
{
    // Contains ordered set of UIInfo and Entity elements.
    // We track each one we find, and then consume an Entity by adding.
    // a mapping from the Entity to the last-seen UIInfo.

    const UIInfo* lastSeen = nullptr;

    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        if (XMLHelper::isNodeNamed(child, samlconstants::SAML20MD_UI_NS, UIInfo::LOCAL_NAME)) {
            boost::shared_ptr<XMLObject> obj(UIInfoBuilder::buildOneFromElement(child));
            m_infos.push_back(boost::dynamic_pointer_cast<UIInfo>(obj));
            lastSeen = m_infos.back().get();
        }
        else if (XMLString::equals(child->getLocalName(), Entity)) {
            const XMLCh* eid = XMLHelper::getTextContent(child);
            if (eid && *eid && lastSeen) {
                m_applyMap.insert(applymap_t::value_type(eid, lastSeen));
            }
        }
        else {
            m_log.warn("ignoring unrecognized element, one of mdui:UIInfo or Entity required");
        }
        child = XMLHelper::getNextSiblingElement(child);
    }

    if (m_applyMap.empty()) {
        m_log.warn("UIInfo filter has no rules to apply");
    }
}

void UIInfoMetadataFilter::doFilter(const MetadataFilterContext*, XMLObject& xmlObject) const
{
    if (m_applyMap.empty())
        return;

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
            throw MetadataFilterException(UIINFO_METADATA_FILTER " MetadataFilter was given an improper metadata instance to filter.");
        }
    }
}

void UIInfoMetadataFilter::filterGroup(EntitiesDescriptor* entities) const
{
    const vector<EntityDescriptor*>& v = const_cast<const EntitiesDescriptor*>(entities)->getEntityDescriptors();
    for_each(v.begin(), v.end(), lambda::bind(&UIInfoMetadataFilter::filterEntity, this, _1));

    const vector<EntitiesDescriptor*>& v2 = const_cast<const EntitiesDescriptor*>(entities)->getEntitiesDescriptors();
    for_each(v2.begin(), v2.end(), lambda::bind(&UIInfoMetadataFilter::filterGroup, this, _1));
}

void UIInfoMetadataFilter::filterEntity(EntityDescriptor* entity) const
{
    if (!entity->getEntityID())
        return;

    applymap_t::const_iterator uiinfo = m_applyMap.find(entity->getEntityID());
    if (uiinfo == m_applyMap.end())
        return;

    VectorOf(IDPSSODescriptor) roles = entity->getIDPSSODescriptors();
    for (VectorOf(IDPSSODescriptor)::iterator i = roles.begin(); i != roles.end(); ++i) {
        Extensions* ext = getContainer(*i);
        if (ext) {
            auto_ptr<UIInfo> dup(uiinfo->second->cloneUIInfo());
            ext->getUnknownXMLObjects().push_back(dup.get());
            dup.release();
        }
    }
}

Extensions* UIInfoMetadataFilter::getContainer(IDPSSODescriptor* role) const
{
    Extensions* exts = role->getExtensions();
    if (!exts) {
        role->setExtensions(ExtensionsBuilder::buildExtensions());
        return role->getExtensions();
    }

    VectorOf(XMLObject) children = exts->getUnknownXMLObjects();
    for (VectorOf(XMLObject)::iterator i = children.begin(); i != children.end(); ++i) {
        if (dynamic_cast<UIInfo*>(*i)) {
            if (!m_replace)
                return nullptr;
            children.erase(i);
            break;
        }
    }

    return exts;
}
