/*
 *  Copyright 2001-2007 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "internal.h"

#include <saml/SAMLConfig.h>
#include <saml/binding/SecurityPolicyRule.h>
#include <saml/saml1/core/Assertions.h>

using namespace opensaml;

class SAML1PolicyTest : public CxxTest::TestSuite {
    SecurityPolicy* m_policy;
    SecurityPolicyRule* m_rule;
public:
    void setUp() {
        m_policy = NULL;
        m_rule = NULL;
        m_rule = SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(CONDITIONS_POLICY_RULE, NULL);
        m_policy = new SecurityPolicy();
        m_policy->getRules().push_back(m_rule);
    }

    void tearDown() {
        delete m_rule;
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
