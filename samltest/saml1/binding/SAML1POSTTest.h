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

#include "binding.h"

#include <saml/saml1/core/Protocols.h>

using namespace opensaml::saml1p;
using namespace opensaml::saml1;

class SAML1POSTTest : public CxxTest::TestSuite, public SAMLBindingBaseTestCase {
public:
    void setUp() {
        SAMLBindingBaseTestCase::setUp();
    }

    void tearDown() {
        SAMLBindingBaseTestCase::tearDown();
    }

    void testSAML1POST() {
        try {
            xmltooling::QName idprole(samlconstants::SAML20MD_NS, IDPSSODescriptor::LOCAL_NAME);
            SecurityPolicy policy(m_metadata.get(), &idprole, m_trust.get(), false);
            policy.getRules().assign(m_rules.begin(), m_rules.end());

            // Read message to use from file.
            string path = data_path + "saml1/binding/SAML1Response.xml";
            ifstream in(path.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
            auto_ptr<Response> toSend(
                dynamic_cast<Response*>(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(),true))
                );
            janitor.release();

            CredentialCriteria cc;
            cc.setUsage(Credential::SIGNING_CREDENTIAL);
            Locker clocker(m_creds.get());
            const Credential* cred = m_creds->resolve(&cc);
            TSM_ASSERT("Retrieved credential was null", cred!=nullptr);

            // Freshen timestamp and ID.
            toSend->setIssueInstant(time(nullptr));
            toSend->setResponseID(nullptr);
    
            // Encode message.
            auto_ptr_XMLCh lit1("MessageEncoder");
            auto_ptr_XMLCh lit2("template");
            path = data_path + "binding/template.html";
            auto_ptr_XMLCh lit3(path.c_str());
            DOMDocument* encoder_config = XMLToolingConfig::getConfig().getParser().newDocument();
            XercesJanitor<DOMDocument> janitor2(encoder_config);
            encoder_config->appendChild(encoder_config->createElementNS(nullptr,lit1.get()));
            encoder_config->getDocumentElement()->setAttributeNS(nullptr,lit2.get(),lit3.get());
            scoped_ptr<MessageEncoder> encoder(
                SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                    samlconstants::SAML1_PROFILE_BROWSER_POST, encoder_config->getDocumentElement()
                    )
                );

            Locker locker(m_metadata.get());
            encoder->encode(
                *this,
                toSend.get(),
                "https://sp.example.org/SAML/SSO",
                m_metadata->getEntityDescriptor(MetadataProvider::Criteria("https://sp.example.org/")).first,
                "state",
                nullptr,
                cred
                );
            toSend.release();
            
            // Decode message.
            string relayState;
            scoped_ptr<MessageDecoder> decoder(
                SAMLConfig::getConfig().MessageDecoderManager.newPlugin(samlconstants::SAML1_PROFILE_BROWSER_POST, nullptr)
                );
            scoped_ptr<Response> response(dynamic_cast<Response*>(decoder->decode(relayState,*this,policy)));
            
            // Test the results.
            TSM_ASSERT_EQUALS("TARGET was not the expected result.", relayState, "state");
            TSM_ASSERT("SAML Response not decoded successfully.", response.get());
            TSM_ASSERT("Message was not verified.", policy.isAuthenticated());
            auto_ptr_char entityID(policy.getIssuer()->getName());
            TSM_ASSERT("Issuer was not expected.", !strcmp(entityID.get(),"https://idp.example.org/"));
            TSM_ASSERT_EQUALS("Assertion count was not correct.", response->getAssertions().size(), 1);

            // Trigger a replay.
            policy.reset();
            TSM_ASSERT_THROWS("Did not catch the replay.", decoder->decode(relayState,*this,policy), SecurityPolicyException);
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }
};
