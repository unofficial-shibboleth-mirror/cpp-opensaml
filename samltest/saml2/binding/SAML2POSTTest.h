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

#include "binding.h"

#include <saml/saml2/core/Protocols.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2;

class SAML2POSTTest : public CxxTest::TestSuite, public SAMLBindingBaseTestCase {
public:
    void setUp() {
        SAMLBindingBaseTestCase::setUp();
    }

    void tearDown() {
        SAMLBindingBaseTestCase::tearDown();
    }

    void testSAML2POST() {
        try {
            QName idprole(samlconstants::SAML20MD_NS, IDPSSODescriptor::LOCAL_NAME);
            SecurityPolicy policy(m_metadata, &idprole, m_trust, false);
            policy.getRules().assign(m_rules2.begin(), m_rules2.end());

            // Read message to use from file.
            string path = data_path + "saml2/binding/SAML2Response.xml";
            ifstream in(path.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
            auto_ptr<Response> toSend(
                dynamic_cast<Response*>(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(),true))
                );
            janitor.release();

            CredentialCriteria cc;
            cc.setUsage(CredentialCriteria::SIGNING_CREDENTIAL);
            Locker clocker(m_creds);
            const Credential* cred = m_creds->resolve(&cc);
            TSM_ASSERT("Retrieved credential was null", cred!=NULL);

            // Freshen timestamp and ID.
            toSend->setIssueInstant(time(NULL));
            toSend->setID(NULL);
    
            // Encode message.
            auto_ptr_XMLCh lit1("MessageEncoder");
            auto_ptr_XMLCh lit2("template");
            path = data_path + "binding/template.html";
            auto_ptr_XMLCh lit3(path.c_str());
            DOMDocument* encoder_config = XMLToolingConfig::getConfig().getParser().newDocument();
            XercesJanitor<DOMDocument> janitor2(encoder_config);
            encoder_config->appendChild(encoder_config->createElementNS(NULL,lit1.get()));
            encoder_config->getDocumentElement()->setAttributeNS(NULL,lit2.get(),lit3.get());
            auto_ptr<MessageEncoder> encoder(
                SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                    samlconstants::SAML20_BINDING_HTTP_POST, pair<const DOMElement*,const XMLCh*>(encoder_config->getDocumentElement(), NULL)
                    )
                );
            Locker locker(m_metadata);
            encoder->encode(
                *this,toSend.get(),"https://sp.example.org/SAML/SSO",m_metadata->getEntityDescriptor("https://sp.example.org/"),"state",NULL,cred
                );
            toSend.release();
            
            // Decode message.
            string relayState;
            auto_ptr<MessageDecoder> decoder(
                SAMLConfig::getConfig().MessageDecoderManager.newPlugin(
                    samlconstants::SAML20_BINDING_HTTP_POST, pair<const DOMElement*,const XMLCh*>(NULL,NULL)
                    )
                );
            auto_ptr<Response> response(dynamic_cast<Response*>(decoder->decode(relayState,*this,policy)));
            
            // Test the results.
            TSM_ASSERT_EQUALS("RelayState was not the expected result.", relayState, "state");
            TSM_ASSERT("SAML Response not decoded successfully.", response.get());
            TSM_ASSERT("Message was not verified.", policy.isSecure());
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

    void testSAML2POSTSimpleSign() {
        try {
            QName idprole(samlconstants::SAML20MD_NS, IDPSSODescriptor::LOCAL_NAME);
            SecurityPolicy policy(m_metadata, &idprole, m_trust, false);
            policy.getRules().assign(m_rules2.begin(), m_rules2.end());

            // Read message to use from file.
            string path = data_path + "saml2/binding/SAML2Response.xml";
            ifstream in(path.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
            auto_ptr<Response> toSend(
                dynamic_cast<Response*>(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(),true))
                );
            janitor.release();

            CredentialCriteria cc;
            cc.setUsage(CredentialCriteria::SIGNING_CREDENTIAL);
            Locker clocker(m_creds);
            const Credential* cred = m_creds->resolve(&cc);
            TSM_ASSERT("Retrieved credential was null", cred!=NULL);

            // Freshen timestamp and ID.
            toSend->setIssueInstant(time(NULL));
            toSend->setID(NULL);
    
            // Encode message.
            auto_ptr_XMLCh lit1("MessageEncoder");
            auto_ptr_XMLCh lit2("template");
            path = data_path + "binding/template.html";
            auto_ptr_XMLCh lit3(path.c_str());
            DOMDocument* encoder_config = XMLToolingConfig::getConfig().getParser().newDocument();
            XercesJanitor<DOMDocument> janitor2(encoder_config);
            encoder_config->appendChild(encoder_config->createElementNS(NULL,lit1.get()));
            encoder_config->getDocumentElement()->setAttributeNS(NULL,lit2.get(),lit3.get());
            auto_ptr<MessageEncoder> encoder(
                SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                    samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN, pair<const DOMElement*,const XMLCh*>(encoder_config->getDocumentElement(),NULL)
                    )
                );
            Locker locker(m_metadata);
            encoder->encode(
                *this,toSend.get(),"https://sp.example.org/SAML/SSO",m_metadata->getEntityDescriptor("https://sp.example.org/"),"state",NULL,cred
                );
            toSend.release();
            
            // Decode message.
            string relayState;
            auto_ptr<MessageDecoder> decoder(
                SAMLConfig::getConfig().MessageDecoderManager.newPlugin(
                    samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN, pair<const DOMElement*,const XMLCh*>(NULL,NULL)
                    )
                );
            auto_ptr<Response> response(dynamic_cast<Response*>(decoder->decode(relayState,*this,policy)));
            
            // Test the results.
            TSM_ASSERT_EQUALS("RelayState was not the expected result.", relayState, "state");
            TSM_ASSERT("SAML Response not decoded successfully.", response.get());
            TSM_ASSERT("Message was not verified.", policy.isSecure());
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
