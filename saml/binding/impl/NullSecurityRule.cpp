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
 * NullSecurityRule.cpp
 * 
 * SecurityPolicyRule that "disables" security. 
 */

#include "internal.h"
#include "binding/SecurityPolicy.h"
#include "binding/SecurityPolicyRule.h"

#include <xmltooling/logging.h>

using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    class SAML_DLLLOCAL NullSecurityRule : public SecurityPolicyRule
    {
    public:
        NullSecurityRule(const DOMElement* e)
            : SecurityPolicyRule(e), m_log(Category::getInstance(SAML_LOGCAT ".SecurityPolicyRule.NullSecurity")) {}
        virtual ~NullSecurityRule() {}
        
        const char* getType() const {
            return NULLSECURITY_POLICY_RULE;
        }
        bool evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const {
            if (!SecurityPolicyRule::evaluate(message, request, policy)) {
                return false;
            }

            m_log.warn("security enforced using NULL policy rule, be sure you know what you're doing");
            policy.setAuthenticated(true);
            return true;
        }

    private:
        Category& m_log;
    };

    SecurityPolicyRule* SAML_DLLLOCAL NullSecurityRuleFactory(const DOMElement* const & e, bool)
    {
        return new NullSecurityRule(e);
    }
};
