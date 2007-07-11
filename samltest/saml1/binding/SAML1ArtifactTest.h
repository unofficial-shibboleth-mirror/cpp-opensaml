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

#include <saml/binding/ArtifactMap.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml1/binding/SAMLArtifactType0001.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml1p;
using namespace opensaml::saml1;

class SAML1ArtifactTest : public CxxTest::TestSuite,
        public SAMLBindingBaseTestCase, public MessageEncoder::ArtifactGenerator, public MessageDecoder::ArtifactResolver {
public:
    void setUp() {
        SAMLBindingBaseTestCase::setUp();
    }

    void tearDown() {
        SAMLBindingBaseTestCase::tearDown();
    }

    void testSAML1Artifact() {
        try {
            QName idprole(samlconstants::SAML20MD_NS, IDPSSODescriptor::LOCAL_NAME);
            SecurityPolicy policy(m_rules1, m_metadata, &idprole, m_trust, false);

            // Read message to use from file.
            string path = data_path + "saml1/binding/SAML1Assertion.xml";
            ifstream in(path.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
            auto_ptr<saml1::Assertion> toSend(
                dynamic_cast<saml1::Assertion*>(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(),true))
                );
            janitor.release();

            CredentialCriteria cc;
            cc.setUsage(CredentialCriteria::SIGNING_CREDENTIAL);
            Locker clocker(m_creds);
            const Credential* cred = m_creds->resolve(&cc);
            TSM_ASSERT("Retrieved credential was null", cred!=NULL);

            // Encode message.
            auto_ptr<MessageEncoder> encoder(
                SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                    samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT, pair<const DOMElement*,const XMLCh*>(NULL,NULL)
                    )
                );
            Locker locker(m_metadata);
            encoder->encode(
                *this,toSend.get(),"https://sp.example.org/SAML/SSO",m_metadata->getEntityDescriptor("https://sp.example.org/"),"state",this,cred
                );
            toSend.release();
            
            // Decode message.
            string relayState;
            auto_ptr<MessageDecoder> decoder(
                SAMLConfig::getConfig().MessageDecoderManager.newPlugin(
                    samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT, pair<const DOMElement*,const XMLCh*>(NULL,NULL)
                    )
                );
            decoder->setArtifactResolver(this);
            auto_ptr<Response> response(dynamic_cast<Response*>(decoder->decode(relayState,*this,policy)));
            
            // Test the results.
            TSM_ASSERT_EQUALS("TARGET was not the expected result.", relayState, "state");
            TSM_ASSERT("SAML Response not decoded successfully.", response.get());
            TSM_ASSERT("Message was not verified.", policy.isSecure());
            auto_ptr_char entityID(policy.getIssuer()->getName());
            TSM_ASSERT("Issuer was not expected.", !strcmp(entityID.get(),"https://idp.example.org/"));
            TSM_ASSERT_EQUALS("Assertion count was not correct.", response->getAssertions().size(), 1);

            // Trigger a replay.
            policy.reset();
            TSM_ASSERT_THROWS("Did not catch the replay.", decoder->decode(relayState,*this,policy), BindingException);
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }

    SAMLArtifact* generateSAML1Artifact(const EntityDescriptor* relyingParty) const {
        return new SAMLArtifactType0001(SAMLConfig::getConfig().hashSHA1("https://idp.example.org/"));
    }
    
    saml2p::SAML2Artifact* generateSAML2Artifact(const EntityDescriptor* relyingParty) const {
        throw BindingException("Not implemented.");
    }
    
    Response* resolve(
        const vector<SAMLArtifact*>& artifacts,
        const IDPSSODescriptor& idpDescriptor,
        SecurityPolicy& policy
        ) const {
        TSM_ASSERT_EQUALS("Too many artifacts.", artifacts.size(), 1);
        XMLObject* xmlObject =
            SAMLConfig::getConfig().getArtifactMap()->retrieveContent(artifacts.front(), "https://sp.example.org/");
        saml1::Assertion* assertion = dynamic_cast<saml1::Assertion*>(xmlObject);
        TSM_ASSERT("Not an assertion.", assertion!=NULL);
        auto_ptr<Response> response(ResponseBuilder::buildResponse());
        response->getAssertions().push_back(assertion);
        Status* status = StatusBuilder::buildStatus();
        response->setStatus(status);
        StatusCode* sc = StatusCodeBuilder::buildStatusCode();
        status->setStatusCode(sc);
        sc->setValue(&StatusCode::SUCCESS);
        response->setSignature(SignatureBuilder::buildSignature());
        vector<Signature*> sigs(1,response->getSignature());
        CredentialCriteria cc;
        cc.setUsage(CredentialCriteria::SIGNING_CREDENTIAL);
        Locker clocker(m_creds);
        const Credential* cred = m_creds->resolve(&cc);
        TSM_ASSERT("Retrieved credential was null", cred!=NULL);
        response->marshall((DOMDocument*)NULL,&sigs,cred);
        SchemaValidators.validate(response.get());
        policy.evaluate(*(response.get()), this);
        return response.release();
    }

    saml2p::ArtifactResponse* resolve(
        const saml2p::SAML2Artifact& artifact,
        const SSODescriptorType& ssoDescriptor,
        SecurityPolicy& policy
        ) const {
        throw BindingException("Not implemented.");
    }
};
