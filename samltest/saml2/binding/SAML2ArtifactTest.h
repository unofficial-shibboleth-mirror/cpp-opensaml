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

#include <saml/binding/ArtifactMap.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/binding/SAML2ArtifactType0004.h>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2;

class SAML2ArtifactTest : public CxxTest::TestSuite,
        public SAMLBindingBaseTestCase, public MessageEncoder::ArtifactGenerator, public MessageDecoder::ArtifactResolver {
public:
    void setUp() {
        SAMLBindingBaseTestCase::setUp();
    }

    void tearDown() {
        SAMLBindingBaseTestCase::tearDown();
    }

    void testSAML2Artifact() {
        try {
            xmltooling::QName idprole(samlconstants::SAML20MD_NS, IDPSSODescriptor::LOCAL_NAME);
            SecurityPolicy policy(m_metadata.get(), &idprole, m_trust.get(), false);
            policy.getRules().assign(m_rules.begin(), m_rules.end());

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
            cc.setUsage(Credential::SIGNING_CREDENTIAL);
            Locker clocker(m_creds.get());
            const Credential* cred = m_creds->resolve(&cc);
            TSM_ASSERT("Retrieved credential was null", cred!=nullptr);

            // Freshen timestamp.
            toSend->setIssueInstant(time(nullptr));

            // Encode message.
            scoped_ptr<MessageEncoder> encoder(
                SAMLConfig::getConfig().MessageEncoderManager.newPlugin(samlconstants::SAML20_BINDING_HTTP_ARTIFACT, nullptr, false)
                );
            Locker locker(m_metadata.get());
            encoder->encode(
                *this,
                toSend.get(),
                "https://sp.example.org/SAML/SSO",
                m_metadata->getEntityDescriptor(MetadataProvider::Criteria("https://sp.example.org/")).first,
                "state",
                this,
                cred
                );
            toSend.release();
            
            // Decode message.
            string relayState;
            scoped_ptr<MessageDecoder> decoder(
                SAMLConfig::getConfig().MessageDecoderManager.newPlugin(samlconstants::SAML20_BINDING_HTTP_ARTIFACT, nullptr, false)
                );
            decoder->setArtifactResolver(this);
            scoped_ptr<Response> response(dynamic_cast<Response*>(decoder->decode(relayState,*this,policy)));
            
            // Test the results.
            TSM_ASSERT_EQUALS("RelayState was not the expected result.", relayState, "state");
            TSM_ASSERT("SAML Response not decoded successfully.", response.get());
            TSM_ASSERT("Message was not verified.", policy.isAuthenticated());
            auto_ptr_char entityID(policy.getIssuer()->getName());
            TSM_ASSERT("Issuer was not expected.", !strcmp(entityID.get(),"https://idp.example.org/"));
            TSM_ASSERT_EQUALS("Assertion count was not correct.", response->getAssertions().size(), 1);

            // Trigger a replay.
            policy.reset();
            TSM_ASSERT_THROWS("Did not catch the replay.", decoder->decode(relayState,*this,policy), BindingException);
        }
        catch (const XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }
    
    SAMLArtifact* generateSAML1Artifact(const EntityDescriptor* relyingParty) const {
        throw BindingException("Not implemented.");
    }
    
    saml2p::SAML2Artifact* generateSAML2Artifact(const EntityDescriptor* relyingParty) const {
        static const char* providerIdStr = "https://idp.example.org/";
        return new SAML2ArtifactType0004(
            SecurityHelper::doHash("SHA1", providerIdStr, strlen(providerIdStr), false), 1
            );
    }
    
    saml1p::Response* resolve(
        const vector<SAMLArtifact*>& artifacts,
        const IDPSSODescriptor& idpDescriptor,
        SecurityPolicy& policy
        ) const {
        throw BindingException("Not implemented.");
    }

    ArtifactResponse* resolve(
        const SAML2Artifact& artifact,
        const SSODescriptorType& ssoDescriptor,
        SecurityPolicy& policy
        ) const {
        XMLObject* xmlObject =
            SAMLConfig::getConfig().getArtifactMap()->retrieveContent(&artifact, "https://sp.example.org/");
        Response* payload = dynamic_cast<Response*>(xmlObject);
        TSM_ASSERT("Not a response.", payload!=nullptr);

        auto_ptr<ArtifactResponse> response(ArtifactResponseBuilder::buildArtifactResponse());
        response->setPayload(payload);
        saml2p::Status* status = StatusBuilder::buildStatus();
        response->setStatus(status);
        StatusCode* sc = StatusCodeBuilder::buildStatusCode();
        status->setStatusCode(sc);
        sc->setValue(StatusCode::SUCCESS);
        response->marshall();
        SchemaValidators.validate(response.get());
        policy.evaluate(*response, this);
        return response.release();
    }
};
