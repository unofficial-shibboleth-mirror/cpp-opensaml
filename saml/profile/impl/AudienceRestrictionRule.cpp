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
 * AudienceRestrictionRule.cpp
 *
 * SAML AudienceRestriction SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicy.h"
#include "binding/SecurityPolicyRule.h"
#include "saml1/core/Assertions.h"
#include "saml2/core/Assertions.h"

#include <xmltooling/logging.h>

using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    class SAML_DLLLOCAL AudienceRestrictionRule : public SecurityPolicyRule
    {
    public:
        AudienceRestrictionRule(const DOMElement* e);

        virtual ~AudienceRestrictionRule() {
        }
        const char* getType() const {
            return AUDIENCE_POLICY_RULE;
        }
        bool evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;

    private:
        vector<const XMLCh*> m_audiences;
    };

    SecurityPolicyRule* SAML_DLLLOCAL AudienceRestrictionRuleFactory(const DOMElement* const & e)
    {
        return new AudienceRestrictionRule(e);
    }
};

AudienceRestrictionRule::AudienceRestrictionRule(const DOMElement* e)
{
    e = e ? XMLHelper::getFirstChildElement(e, saml2::Audience::LOCAL_NAME) : nullptr;
    while (e) {
        if (e->hasChildNodes())
            m_audiences.push_back(e->getFirstChild()->getNodeValue());
        e = XMLHelper::getNextSiblingElement(e, saml2::Audience::LOCAL_NAME);
    }
}

bool AudienceRestrictionRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    const saml2::AudienceRestriction* ac2=dynamic_cast<const saml2::AudienceRestriction*>(&message);
    if (ac2) {
        const vector<saml2::Audience*>& auds2 = ac2->getAudiences();
        for (vector<saml2::Audience*>::const_iterator a1 = auds2.begin(); a1!=auds2.end(); ++a1) {
            for (vector<xstring>::const_iterator a2 = policy.getAudiences().begin(); a2!=policy.getAudiences().end(); ++a2) {
                if (XMLString::equals((*a1)->getAudienceURI(), a2->c_str()))
                    return true;
            }
            for (vector<const XMLCh*>::const_iterator a2 = m_audiences.begin(); a2!=m_audiences.end(); ++a2) {
                if (XMLString::equals((*a1)->getAudienceURI(), *a2))
                    return true;
            }
        }

        ostringstream os;
        os << *ac2;
        Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.AudienceRestriction").error(
            "unacceptable AudienceRestriction in assertion (%s)", os.str().c_str()
            );
        throw SecurityPolicyException("Assertion contains an unacceptable AudienceRestriction.");
    }

    const saml1::AudienceRestrictionCondition* ac1=dynamic_cast<const saml1::AudienceRestrictionCondition*>(&message);
    if (ac1) {
        const vector<saml1::Audience*>& auds1 = ac1->getAudiences();
        for (vector<saml1::Audience*>::const_iterator a1 = auds1.begin(); a1!=auds1.end(); ++a1) {
            for (vector<xstring>::const_iterator a2 = policy.getAudiences().begin(); a2!=policy.getAudiences().end(); ++a2) {
                if (XMLString::equals((*a1)->getAudienceURI(), a2->c_str()))
                    return true;
            }
            for (vector<const XMLCh*>::const_iterator a2 = m_audiences.begin(); a2!=m_audiences.end(); ++a2) {
                if (XMLString::equals((*a1)->getAudienceURI(), *a2))
                    return true;
            }
        }

        ostringstream os;
        os << *ac1;
        Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.AudienceRestriction").error(
            "unacceptable AudienceRestrictionCondition in assertion (%s)", os.str().c_str()
            );
        throw SecurityPolicyException("Assertion contains an unacceptable AudienceRestrictionCondition.");
    }

    return false;
}
