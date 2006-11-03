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

namespace {
    class SAML_DLLLOCAL _addcert : public binary_function<X509Data*,XSECCryptoX509*,void> {
    public:
        void operator()(X509Data* bag, XSECCryptoX509* cert) const {
            safeBuffer& buf=cert->getDEREncodingSB();
            X509Certificate* x=X509CertificateBuilder::buildX509Certificate();
            x->setValue(buf.sbStrToXMLCh());
            bag->getX509Certificates().push_back(x);
        }
    };
};

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
            SecurityPolicy policy(m_rules, m_metadata, &idprole, m_trust);

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
            auto_ptr<MessageEncoder> encoder(
                SAMLConfig::getConfig().MessageEncoderManager.newPlugin(samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT, NULL)
                );
            encoder->setArtifactGenerator(this);
            encoder->encode(*this,toSend.get(),"https://sp.example.org/SAML/Artifact","https://sp.example.org/","state",m_creds);
            toSend.release();
            
            // Decode message.
            string relayState;
            auto_ptr<MessageDecoder> decoder(
                SAMLConfig::getConfig().MessageDecoderManager.newPlugin(samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT, NULL)
                );
            decoder->setArtifactResolver(this);
            Locker locker(m_metadata);
            auto_ptr<Response> response(dynamic_cast<Response*>(decoder->decode(relayState,*this,policy)));
            
            // Test the results.
            TSM_ASSERT_EQUALS("TARGET was not the expected result.", relayState, "state");
            TSM_ASSERT("SAML Response not decoded successfully.", response.get());
            TSM_ASSERT("Message was not verified.", policy.getIssuer()!=NULL);
            auto_ptr_char entityID(policy.getIssuer()->getName());
            TSM_ASSERT("Issuer was not expected.", !strcmp(entityID.get(),"https://idp.example.org/"));
            TSM_ASSERT_EQUALS("Assertion count was not correct.", response->getAssertions().size(), 1);

            // Trigger a replay.
            TSM_ASSERT_THROWS("Did not catch the replay.", decoder->decode(relayState,*this,policy), BindingException);
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }

    SAMLArtifact* generateSAML1Artifact(const char* relyingParty) const {
        return new SAMLArtifactType0001(SAMLConfig::getConfig().hashSHA1("https://idp.example.org/"));
    }
    
    saml2p::SAML2Artifact* generateSAML2Artifact(const char* relyingParty) const {
        throw BindingException("Not implemented.");
    }
    
    Signature* buildSignature(const CredentialResolver* credResolver) const
    {
        // Build a Signature.
        Signature* sig = SignatureBuilder::buildSignature();
        sig->setSigningKey(credResolver->getKey());

        // Build KeyInfo.
        const vector<XSECCryptoX509*>& certs = credResolver->getCertificates();
        if (!certs.empty()) {
            KeyInfo* keyInfo=KeyInfoBuilder::buildKeyInfo();
            X509Data* x509Data=X509DataBuilder::buildX509Data();
            keyInfo->getX509Datas().push_back(x509Data);
            for_each(certs.begin(),certs.end(),bind1st(_addcert(),x509Data));
            sig->setKeyInfo(keyInfo);
        }
        
        return sig;
    }

    Response* resolve(
        const vector<SAMLArtifact*>& artifacts,
        const IDPSSODescriptor& idpDescriptor,
        SecurityPolicy& policy
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
        response->setSignature(buildSignature(m_creds));
        vector<Signature*> sigs(1,response->getSignature());
        response->marshall((DOMDocument*)NULL,&sigs);
        SchemaValidators.validate(response.get());
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