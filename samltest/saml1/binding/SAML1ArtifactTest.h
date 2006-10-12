/*
 *  Copyright 2001-2005 Internet2
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
        m_fields.clear();
        SAMLBindingBaseTestCase::setUp();
    }

    void tearDown() {
        m_fields.clear();
        SAMLBindingBaseTestCase::tearDown();
    }

    void testSAML1Artifact() {
        try {
            // Read message to use from file.
            string path = data_path + "saml1/binding/SAML1Assertion.xml";
            ifstream in(path.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
            auto_ptr<Assertion> toSend(
                dynamic_cast<Assertion*>(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(),true))
                );
            janitor.release();

            // Encode message.
            auto_ptr<MessageEncoder> encoder(SAMLConfig::getConfig().MessageEncoderManager.newPlugin(SAML1_ARTIFACT_ENCODER, NULL));
            encoder->setArtifactGenerator(this);
            encoder->encode(m_fields,toSend.get(),"https://sp.example.org/","state",m_creds);
            toSend.release();
            
            // Decode message.
            string relayState;
            const RoleDescriptor* issuer=NULL;
            bool trusted=false;
            QName idprole(SAMLConstants::SAML20MD_NS, IDPSSODescriptor::LOCAL_NAME);
            auto_ptr<MessageDecoder> decoder(SAMLConfig::getConfig().MessageDecoderManager.newPlugin(SAML1_ARTIFACT_DECODER, NULL));
            decoder->setArtifactResolver(this);
            Locker locker(m_metadata);
            auto_ptr<Response> response(
                dynamic_cast<Response*>(
                    decoder->decode(relayState,issuer,trusted,*this,m_metadata,&idprole,m_trust)
                    )
                );
            
            // Test the results.
            TSM_ASSERT_EQUALS("TARGET was not the expected result.", relayState, "state");
            TSM_ASSERT("SAML Response not decoded successfully.", response.get());
            TSM_ASSERT("Message was not verified.", issuer && trusted);
            auto_ptr_char entityID(dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getEntityID());
            TSM_ASSERT("Issuer was not expected.", !strcmp(entityID.get(),"https://idp.example.org/"));
            TSM_ASSERT_EQUALS("Assertion count was not correct.", response->getAssertions().size(), 1);

            // Trigger a replay.
            TSM_ASSERT_THROWS("Did not catch the replay.", 
                decoder->decode(relayState,issuer,trusted,*this,m_metadata,&idprole,m_trust),
                BindingException);
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }

    const char* getMethod() const {
        return "GET";
    } 

    const char* getRequestURL() const {
        return "https://sp.example.org/SAML/Artifact";
    }
    
    const char* getQueryString() const {
        return NULL;
    }
    
    SAMLArtifact* generateSAML1Artifact(const char* relyingParty) const {
        return new SAMLArtifactType0001(SAMLConfig::getConfig().hashSHA1("https://idp.example.org/"));
    }
    
    saml2p::SAML2Artifact* generateSAML2Artifact(const char* relyingParty) const {
        throw BindingException("Not implemented.");
    }
    
    Response* resolve(
        bool& authenticated,
        const vector<SAMLArtifact*>& artifacts,
        const IDPSSODescriptor& idpDescriptor,
        const X509TrustEngine* trustEngine=NULL
        ) const {
        TSM_ASSERT_EQUALS("Too many artifacts.", artifacts.size(), 1);
        XMLObject* xmlObject =
            SAMLConfig::getConfig().getArtifactMap()->retrieveContent(artifacts.front(), "https://sp.example.org/");
        Assertion* assertion = dynamic_cast<Assertion*>(xmlObject);
        TSM_ASSERT("Not an assertion.", assertion!=NULL);
        auto_ptr<Response> response(ResponseBuilder::buildResponse());
        response->getAssertions().push_back(assertion);
        Status* status = StatusBuilder::buildStatus();
        response->setStatus(status);
        StatusCode* sc = StatusCodeBuilder::buildStatusCode();
        status->setStatusCode(sc);
        sc->setValue(&StatusCode::SUCCESS);
        response->marshall();
        SchemaValidators.validate(response.get());
        authenticated = true;
        return response.release();
    }

    saml2p::ArtifactResponse* resolve(
        bool& authenticated,
        const saml2p::SAML2Artifact& artifact,
        const SSODescriptorType& ssoDescriptor,
        const X509TrustEngine* trustEngine=NULL
        ) const {
        throw BindingException("Not implemented.");
    }
};
