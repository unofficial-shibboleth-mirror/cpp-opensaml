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
 * RegistrationAuthorityEntityMatcher.cpp
 *
 * EntityMatcher that matches based on RPI registrationAuthority.
 */

#include "internal.h"
#include "saml2/metadata/EntityMatcher.h"
#include "saml2/metadata/Metadata.h"

#include <boost/lambda/bind.hpp>
#include <boost/lambda/casts.hpp>
#include <boost/lambda/lambda.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
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
        class SAML_DLLLOCAL RegistrationAuthorityEntityMatcher : public EntityMatcher
        {
        public:
            RegistrationAuthorityEntityMatcher(const DOMElement* e);
            ~RegistrationAuthorityEntityMatcher() {}

            bool matches(const EntityDescriptor& entity) const;

        private:
            set<xstring> m_authorities;
            Category& m_log;
        };

        EntityMatcher* SAML_DLLLOCAL RegistrationAuthorityEntityMatcherFactory(const DOMElement* const & e, bool deprecationSupport)
        {
            return new RegistrationAuthorityEntityMatcher(e);
        }
    };
};


RegistrationAuthorityEntityMatcher::RegistrationAuthorityEntityMatcher(const DOMElement* e)
    : m_log(Category::getInstance(SAML_LOGCAT ".EntityMatcher.RegistrationAuthority"))
{
    // Check for shorthand syntax.
    if (e && e->hasAttributeNS(nullptr, RegistrationInfo::REGAUTHORITY_ATTRIB_NAME)) {
        m_authorities.insert(e->getAttributeNS(nullptr, RegistrationInfo::REGAUTHORITY_ATTRIB_NAME));
    }

    const DOMElement* child = XMLHelper::getFirstChildElement(e, RegistrationInfo::REGAUTHORITY_ATTRIB_NAME);
    while (child) {
        const XMLCh* text = child->getTextContent();
        if (text && *text) {
            m_authorities.insert(text);
        }
        child = XMLHelper::getNextSiblingElement(child, RegistrationInfo::REGAUTHORITY_ATTRIB_NAME);
    }

    if (m_authorities.empty())
        throw XMLToolingException("RegistrationAuthority EntityMatcher requires at least one authority to match.");
}

bool RegistrationAuthorityEntityMatcher::matches(const EntityDescriptor& entity) const
{
    bool extFound = false;

    const Extensions* exts = entity.getExtensions();
    if (exts) {
        const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
        const XMLObject* xo = find_if(children, ll_dynamic_cast<RegistrationInfo*>(_1) != ((RegistrationInfo*)nullptr));
        if (xo) {
            extFound = true;
            const RegistrationInfo* regInfo = dynamic_cast<const RegistrationInfo*>(xo);
            if (regInfo->getRegistrationAuthority() && m_authorities.find(regInfo->getRegistrationAuthority()) != m_authorities.end()) {
                return true;
            }
        }
    }

    const EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(entity.getParent());
    while (group) {
        exts = group->getExtensions();
        if (exts) {
            const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
            const XMLObject* xo = find_if(children, ll_dynamic_cast<RegistrationInfo*>(_1) != ((RegistrationInfo*)nullptr));
            if (xo) {
                extFound = true;
                const RegistrationInfo* regInfo = dynamic_cast<const RegistrationInfo*>(xo);
                if (regInfo->getRegistrationAuthority() && m_authorities.find(regInfo->getRegistrationAuthority()) != m_authorities.end()) {
                    return true;
                }
            }
        }
        group = dynamic_cast<EntitiesDescriptor*>(group->getParent());
    }

    if (!extFound && m_log.isDebugEnabled()) {
        auto_ptr_char id (entity.getEntityID());
        m_log.debug("no RegistrationAuthority extension found for (%s)", id.get());
    }

    return false;
}
