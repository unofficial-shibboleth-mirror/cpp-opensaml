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

#include "internal.h"

#include <saml/SAMLConfig.h>
#include <saml/binding/SecurityPolicy.h>
#include <saml/binding/SecurityPolicyRule.h>
#include <saml/saml1/core/Assertions.h>

using namespace opensaml;

class SAML1PolicyTest : public CxxTest::TestSuite {
    SecurityPolicy* m_policy;
    vector<SecurityPolicyRule*> m_rules;
public:
    void setUp() {
        m_policy = nullptr;
        m_rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(CONDITIONS_POLICY_RULE, nullptr));
        m_rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(SAML1BROWSERSSO_POLICY_RULE, nullptr));
        m_policy = new SecurityPolicy();
        m_policy->getRules().assign(m_rules.begin(), m_rules.end());
    }

    void tearDown() {
        for_each(m_rules.begin(), m_rules.end(), xmltooling::cleanup<SecurityPolicyRule>());
        delete m_policy;
    }

    void testSAML1Policy() {
        try {
            // Read assertion to use from file.
            string path = data_path + "saml1/profile/SAML1Assertion.xml";
            ifstream in(path.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
            auto_ptr<saml1::Assertion> assertion(
                dynamic_cast<saml1::Assertion*>(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(),true))
                );
            janitor.release();

            TSM_ASSERT_THROWS("Policy should have tripped on AudienceRestriction", m_policy->evaluate(*assertion.get()), SecurityPolicyException);

            auto_ptr_XMLCh recipient("https://sp.example.org");
            m_policy->getAudiences().push_back(recipient.get());
            m_policy->evaluate(*assertion.get());
        }
        catch (exception& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }
};
