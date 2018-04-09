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
#include <saml/saml2/core/Assertions.h>

using namespace opensaml;

class SAML2PolicyTest : public CxxTest::TestSuite {
    scoped_ptr<SecurityPolicy> m_policy;
    vector<SecurityPolicyRule*> m_rules;

public:
    void setUp() {
        m_rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(CONDITIONS_POLICY_RULE, nullptr));
        m_rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(BEARER_POLICY_RULE, nullptr));
        m_policy.reset(new SecurityPolicy());
        m_policy->getRules().assign(m_rules.begin(), m_rules.end());
    }

    void tearDown() {
        for_each(m_rules.begin(), m_rules.end(), xmltooling::cleanup<SecurityPolicyRule>());
        m_policy.reset();
    }

    void testSAML2Policy() {
        try {
            // Read assertion to use from file.
            string path = data_path + "saml2/profile/SAML2Assertion.xml";
            ifstream in(path.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
            scoped_ptr<saml2::Assertion> assertion(
                dynamic_cast<saml2::Assertion*>(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(),true))
                );
            janitor.release();

            auto_ptr_XMLCh requestID("_12345");
            m_policy->setCorrelationID(requestID.get());

            TSM_ASSERT_THROWS("Policy should have tripped on AudienceRestriction", m_policy->evaluate(*assertion.get()), SecurityPolicyException);

            auto_ptr_XMLCh recipient("https://sp.example.org");
            m_policy->getAudiences().push_back(recipient.get());
            TSM_ASSERT_THROWS("Policy should have tripped on InResponseTo correlation", m_policy->evaluate(*assertion.get()), SecurityPolicyException);

            dynamic_cast<saml2::SubjectConfirmationData*>(
                assertion->getSubject()->getSubjectConfirmations().front()->getSubjectConfirmationData()
                )->setInResponseTo(requestID.get());
            m_policy->evaluate(*assertion);
        }
        catch (const exception& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }
};
