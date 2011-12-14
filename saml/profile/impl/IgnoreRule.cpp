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
 * IgnoreRule.cpp
 *
 * SecurityPolicyRule that ignores a message while indicating "success".
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"

#include <xmltooling/logging.h>
#include <xmltooling/QName.h>
#include <xmltooling/XMLObject.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;


namespace opensaml {
    class SAML_DLLLOCAL IgnoreRule : public SecurityPolicyRule
    {
    public:
        IgnoreRule(const DOMElement* e)
            : m_log(Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.Ignore")), m_qname(XMLHelper::getNodeValueAsQName(e)) {
            if (!m_qname.get())
                throw SecurityPolicyException("No schema type or element name supplied to Ignore rule.");
        }
        virtual ~IgnoreRule() {}

        const char* getType() const {
            return IGNORE_POLICY_RULE;
        }
        bool evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const {
            if (message.getSchemaType()) {
                if (*m_qname.get() != *(message.getSchemaType()))
                    return false;
                m_log.info("ignoring condition with type (%s)", message.getSchemaType()->toString().c_str());
            }
            else {
                if (*m_qname.get() != message.getElementQName())
                    return false;
                m_log.info("ignoring condition (%s)", message.getElementQName().toString().c_str());
            }
            return true;
        }

    private:
        Category& m_log;
        auto_ptr<xmltooling::QName> m_qname;
    };

    SecurityPolicyRule* SAML_DLLLOCAL IgnoreRuleFactory(const DOMElement* const & e)
    {
        return new IgnoreRule(e);
    }
};
