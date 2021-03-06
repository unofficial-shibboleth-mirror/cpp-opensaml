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
 * DelegationRestrictionRule.cpp
 *
 * SAML DelegationRestriction SecurityPolicyRule.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/core/Assertions.h"
#include "util/SAMLConstants.h"

#include <ctime>
#include <boost/ptr_container/ptr_vector.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>

using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace opensaml {
    namespace saml2 {
        class SAML_DLLLOCAL DelegationRestrictionRule : public SecurityPolicyRule
        {
        public:
            DelegationRestrictionRule(const DOMElement* e);

            virtual ~DelegationRestrictionRule() {
            }
            const char* getType() const {
                return DELEGATION_POLICY_RULE;
            }
            bool evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;

        private:
            ptr_vector<Delegate> m_delegates;
            enum {
                MATCH_ANY,
                MATCH_NEWEST,
                MATCH_OLDEST
            } m_match;
            time_t m_maxTime;
        };

        SecurityPolicyRule* SAML_DLLLOCAL DelegationRestrictionRuleFactory(const DOMElement* const & e, bool)
        {
            return new DelegationRestrictionRule(e);
        }

        class SAML_DLLLOCAL _isSameDelegate : public binary_function<const Delegate*,const Delegate*,bool>,
            public unary_function<const Delegate*,bool>
        {
            const Delegate* m_operand;
            bool isSameFormat(const XMLCh* f1, const XMLCh* f2) const {
                if (!f1 || !*f1)
                    f1 = NameIDType::UNSPECIFIED;
                if (!f2 || !*f2)
                    f2 = NameIDType::UNSPECIFIED;
                return XMLString::equals(f1, f2);
            }
            bool matches(const NameID* n1, const NameID* n2) const {
                return (isSameFormat(n1->getFormat(), n2->getFormat()) &&
                        XMLString::equals(n1->getName(), n2->getName()) &&
                        XMLString::equals(n1->getNameQualifier(), n2->getNameQualifier()) &&
                        XMLString::equals(n1->getSPNameQualifier(), n2->getSPNameQualifier()));
            }
        public:
            _isSameDelegate() : m_operand(nullptr) {}
            _isSameDelegate(const Delegate* d) : m_operand(d) {}

            // d1 is the input from the message, d2 is from the policy
            bool operator()(const Delegate* d1, const Delegate& d2) const {
                if (!d1->getNameID()) {
                    Category::getInstance(SAML_LOGCAT ".SecurityPolicyRule.DelegationRestriction").error(
                        "rule doesn't support evaluation of BaseID or EncryptedID in a Delegate"
                        );
                    return false;
                }
                if (!d2.getConfirmationMethod() || XMLString::equals(d1->getConfirmationMethod(), d2.getConfirmationMethod())) {
                    return matches(d1->getNameID(), d2.getNameID());
                }
                return false;
            }

            // d is from the policy
            bool operator()(const Delegate& d) const {
                return this->operator()(m_operand, d);
            }
        };

        static XMLCh match[] =  UNICODE_LITERAL_5(m,a,t,c,h);
        static XMLCh any[] =    UNICODE_LITERAL_8(a,n,y,O,r,d,e,r);
        static XMLCh newest[] = UNICODE_LITERAL_6(n,e,w,e,s,t);
        static XMLCh oldest[] = UNICODE_LITERAL_6(o,l,d,e,s,t);
        static XMLCh maxTimeSinceDelegation[] = UNICODE_LITERAL_22(m,a,x,T,i,m,e,S,i,n,c,e,D,e,l,e,g,a,t,i,o,n);
    }
};

DelegationRestrictionRule::DelegationRestrictionRule(const DOMElement* e)
    : SecurityPolicyRule(e), m_match(MATCH_ANY), m_maxTime(XMLHelper::getAttrInt(e, 0, maxTimeSinceDelegation))
{
    if (e) {
        const XMLCh* m = e ? e->getAttributeNS(nullptr, match) : nullptr;
        if (XMLString::equals(m, newest))
            m_match = MATCH_NEWEST;
        else if (XMLString::equals(m, oldest))
            m_match = MATCH_OLDEST;
        else if (m && *m && !XMLString::equals(m, any))
            throw SecurityPolicyException("Invalid value for \"match\" attribute in Delegation rule.");

        DOMElement* d = XMLHelper::getFirstChildElement(e, samlconstants::SAML20_DELEGATION_CONDITION_NS, Delegate::LOCAL_NAME);
        while (d) {
            auto_ptr<XMLObject> wrapper(XMLObjectBuilder::buildOneFromElement(d));
            Delegate* down = dynamic_cast<Delegate*>(wrapper.get());
            if (down) {
                m_delegates.push_back(down);
                wrapper.release();
            }
            d = XMLHelper::getNextSiblingElement(d, samlconstants::SAML20_DELEGATION_CONDITION_NS, Delegate::LOCAL_NAME);
        }
    }
}

bool DelegationRestrictionRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    if (!SecurityPolicyRule::evaluate(message, request, policy)) {
        return false;
    }

    const DelegationRestrictionType* drt=dynamic_cast<const DelegationRestrictionType*>(&message);
    if (!drt)
        return false;
    const vector<Delegate*>& dels = drt->getDelegates();

    if (!m_delegates.empty()) {
        if (m_match == MATCH_ANY) {
            // Each Delegate in the condition MUST match an embedded Delegate.
            for (vector<Delegate*>::const_iterator d1 = dels.begin(); d1 != dels.end(); ++d1) {
                if (find_if(m_delegates.begin(), m_delegates.end(), _isSameDelegate(*d1)) == m_delegates.end())
                    return false;
            }
        }
        else if (m_match == MATCH_OLDEST) {
            if (search(dels.begin(), dels.end(), m_delegates.begin(), m_delegates.end(), _isSameDelegate()) != dels.begin())
                return false;
        }
        else if (m_match == MATCH_NEWEST) {
            if (search(dels.rbegin(), dels.rend(), m_delegates.begin(), m_delegates.end(), _isSameDelegate()) != dels.rbegin())
                return false;
        }
    }

    if (m_maxTime > 0) {
        return (!dels.empty() && dels.front()->getDelegationInstant() &&
            (time(nullptr) - dels.front()->getDelegationInstantEpoch() - XMLToolingConfig::getConfig().clock_skew_secs <= m_maxTime));
    }

    return true;
}
