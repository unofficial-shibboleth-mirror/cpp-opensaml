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
 * NameEntityMatcher.cpp
 *
 * EntityMatcher that matches based on name.
 */

#include "internal.h"
#include "saml2/metadata/EntityMatcher.h"
#include "saml2/metadata/Metadata.h"

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {
        class SAML_DLLLOCAL NameEntityMatcher : public EntityMatcher
        {
        public:
            NameEntityMatcher(const DOMElement* e)
                    : m_name(e ? e->getAttributeNS(nullptr, EntitiesDescriptor::NAME_ATTRIB_NAME) : nullptr) {
                if (!m_name || !*m_name)
                    throw XMLToolingException("Name EntityMatcher missing required Name attribute.");
            }
            ~NameEntityMatcher() {}

            bool matches(const EntityDescriptor& entity) const;

        private:
            const XMLCh* m_name;
        };

        EntityMatcher* SAML_DLLLOCAL NameEntityMatcherFactory(const DOMElement* const & e, bool deprecationSupport)
        {
            return new NameEntityMatcher(e);
        }

        SAML_DLLLOCAL PluginManager<EntityMatcher,string,const DOMElement*>::Factory EntityAttributesEntityMatcherFactory;
        SAML_DLLLOCAL PluginManager<EntityMatcher,string,const DOMElement*>::Factory RegistrationAuthorityEntityMatcherFactory;
    };
};

void SAML_API opensaml::saml2md::registerEntityMatchers()
{
    SAMLConfig::getConfig().EntityMatcherManager.registerFactory(NAME_ENTITY_MATCHER, NameEntityMatcherFactory);
    SAMLConfig::getConfig().EntityMatcherManager.registerFactory(ENTITYATTR_ENTITY_MATCHER, EntityAttributesEntityMatcherFactory);
    SAMLConfig::getConfig().EntityMatcherManager.registerFactory(REGAUTH_ENTITY_MATCHER, RegistrationAuthorityEntityMatcherFactory);
}

EntityMatcher::EntityMatcher()
{
}

EntityMatcher::~EntityMatcher()
{
}

bool NameEntityMatcher::matches(const EntityDescriptor& entity) const
{
    if (XMLString::equals(m_name, entity.getEntityID()))
        return true;
    const EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(entity.getParent());
    while (group) {
        if (XMLString::equals(m_name, group->getName()))
            return true;
        group = dynamic_cast<EntitiesDescriptor*>(group->getParent());
    }
    return false;
}
