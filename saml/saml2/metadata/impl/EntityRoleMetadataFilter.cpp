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
 * EntityRoleMetadataFilter.cpp
 *
 * Removes non-whitelisted roles from a metadata instance.
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"

#include <xmltooling/logging.h>

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

using boost::scoped_ptr;

namespace opensaml {
    namespace saml2md {

        class SAML_DLLLOCAL EntityRoleMetadataFilter : public MetadataFilter
        {
        public:
            EntityRoleMetadataFilter(const DOMElement* e);
            ~EntityRoleMetadataFilter() {}

            const char* getId() const { return ENTITYROLE_METADATA_FILTER; }
            void doFilter(XMLObject& xmlObject) const;

        private:
            void doFilter(EntityDescriptor& entity) const;
            void doFilter(EntitiesDescriptor& entities) const;

            bool m_removeRolelessEntityDescriptors, m_removeEmptyEntitiesDescriptors;
            set<xmltooling::QName> m_roles;
            bool m_idp, m_sp, m_authn, m_attr, m_pdp, m_authnq, m_attrq, m_authzq;
        };

        MetadataFilter* SAML_DLLLOCAL EntityRoleMetadataFilterFactory(const DOMElement* const & e)
        {
            return new EntityRoleMetadataFilter(e);
        }

    };
};

static const XMLCh RetainedRole[] =                     UNICODE_LITERAL_12(R,e,t,a,i,n,e,d,R,o,l,e);
static const XMLCh removeRolelessEntityDescriptors[] =  UNICODE_LITERAL_31(r,e,m,o,v,e,R,o,l,e,l,e,s,s,E,n,t,i,t,y,D,e,s,c,r,i,p,t,o,r,s);
static const XMLCh removeEmptyEntitiesDescriptors[] =   UNICODE_LITERAL_30(r,e,m,o,v,e,E,m,p,t,y,E,n,t,i,t,i,e,s,D,e,s,c,r,i,p,t,o,r,s);

EntityRoleMetadataFilter::EntityRoleMetadataFilter(const DOMElement* e)
    : m_removeRolelessEntityDescriptors(XMLHelper::getAttrBool(e, true, removeRolelessEntityDescriptors)),
        m_removeEmptyEntitiesDescriptors(XMLHelper::getAttrBool(e, true, removeEmptyEntitiesDescriptors)),
        m_idp(false), m_sp(false), m_authn(false), m_attr(false), m_pdp(false), m_authnq(false), m_attrq(false), m_authzq(false)
{
    e = XMLHelper::getFirstChildElement(e, RetainedRole);
    while (e) {
        scoped_ptr<xmltooling::QName> q(XMLHelper::getNodeValueAsQName(e));
        if (q) {
            if (*q == IDPSSODescriptor::ELEMENT_QNAME)
                m_idp = true;
            else if (*q == SPSSODescriptor::ELEMENT_QNAME)
                m_sp = true;
            else if (*q == AuthnAuthorityDescriptor::ELEMENT_QNAME)
                m_authn = true;
            else if (*q == AttributeAuthorityDescriptor::ELEMENT_QNAME)
                m_attr = true;
            else if (*q == PDPDescriptor::ELEMENT_QNAME)
                m_pdp = true;
            else if (*q == AuthnQueryDescriptorType::TYPE_QNAME)
                m_authnq = true;
            else if (*q == AttributeQueryDescriptorType::TYPE_QNAME)
                m_attrq = true;
            else if (*q == AuthzDecisionQueryDescriptorType::TYPE_QNAME)
                m_authzq = true;
            else
                m_roles.insert(*q);
        }
        e = XMLHelper::getNextSiblingElement(e, RetainedRole);
    }
}

void EntityRoleMetadataFilter::doFilter(XMLObject& xmlObject) const
{
    EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(&xmlObject);
    if (group) {
        doFilter(*group);
    }
    else {
        EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(&xmlObject);
        if (entity) {
            doFilter(*entity);
        }
        else {
            throw MetadataFilterException(ENTITYROLE_METADATA_FILTER " MetadataFilter was given an improper metadata instance to filter.");
        }
    }
}

void EntityRoleMetadataFilter::doFilter(EntitiesDescriptor& entities) const
{
    Category& log=Category::getInstance(SAML_LOGCAT ".MetadataFilter." ENTITYROLE_METADATA_FILTER);

    VectorOf(EntityDescriptor) v = entities.getEntityDescriptors();
    for (VectorOf(EntityDescriptor)::size_type i = 0; i < v.size(); ) {
        doFilter(*v[i]);
        if (m_removeRolelessEntityDescriptors) {
            const EntityDescriptor& e = const_cast<const EntityDescriptor&>(*v[i]);
            if (e.getIDPSSODescriptors().empty() &&
                    e.getSPSSODescriptors().empty() &&
                    e.getAuthnAuthorityDescriptors().empty() &&
                    e.getAttributeAuthorityDescriptors().empty() &&
                    e.getPDPDescriptors().empty() &&
                    e.getAuthnQueryDescriptorTypes().empty() &&
                    e.getAttributeQueryDescriptorTypes().empty() &&
                    e.getAuthzDecisionQueryDescriptorTypes().empty() &&
                    e.getRoleDescriptors().empty()) {
                auto_ptr_char temp(e.getEntityID());
                log.debug("filtering out role-less entity (%s)", temp.get());
                v.erase(v.begin() + i);
                continue;
            }
        }
        i++;
    }

    VectorOf(EntitiesDescriptor) groups = entities.getEntitiesDescriptors();
    for (VectorOf(EntitiesDescriptor)::size_type j = 0; j < groups.size(); ) {
        EntitiesDescriptor* group = groups[j];
        doFilter(*group);
        if (m_removeEmptyEntitiesDescriptors && group->getEntitiesDescriptors().empty() && group->getEntityDescriptors().empty()) {
            auto_ptr_char temp(entities.getName());
            auto_ptr_char temp2(group->getName());
            log.debug(
                "filtering out empty EntitiesDescriptor (%s) from EntitiesDescriptor (%s)",
                temp2.get() ? temp2.get() : "unnamed",
                temp.get() ? temp.get() : "unnamed"
                );
            groups.erase(groups.begin() + j);
        }
        else {
            j++;
        }
    }
}

void EntityRoleMetadataFilter::doFilter(EntityDescriptor& entity) const
{
    if (!m_idp)
        entity.getIDPSSODescriptors().clear();
    if (!m_sp)
        entity.getSPSSODescriptors().clear();
    if (!m_authn)
        entity.getAuthnAuthorityDescriptors().clear();
    if (!m_attr)
        entity.getAttributeAuthorityDescriptors().clear();
    if (!m_pdp)
        entity.getPDPDescriptors().clear();
    if (!m_authnq)
        entity.getAuthnQueryDescriptorTypes().clear();
    if (!m_attrq)
        entity.getAttributeQueryDescriptorTypes().clear();
    if (!m_authzq)
        entity.getAuthzDecisionQueryDescriptorTypes().clear();

    VectorOf(RoleDescriptor) v = entity.getRoleDescriptors();
    for (VectorOf(RoleDescriptor)::size_type i = 0; i < v.size(); ) {
        const xmltooling::QName* type = v[i]->getSchemaType();
        if (!type || m_roles.find(*type) != m_roles.end())
            v.erase(v.begin() + i);
        else
            i++;
    }
}
