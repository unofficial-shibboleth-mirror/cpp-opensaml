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

#include "signature/SAMLSignatureTestBase.h"

#include <fstream>
#include <sstream>
#include <saml/SAMLConfig.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/saml2/metadata/MetadataCredentialContext.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <xmltooling/security/Credential.h>
#include <xsec/dsig/DSIGConstants.hpp>

using namespace opensaml::saml2md;
using namespace opensaml::saml2;

class EncryptedAssertionTest : public CxxTest::TestSuite, public SAMLSignatureTestBase {
    MetadataProvider* m_metadata;
public:
    void setUp() {
        childElementsFile  = data_path + "signature/SAML2Assertion.xml";
        SAMLSignatureTestBase::setUp();
        
        string config = data_path + "binding/ExampleMetadataProvider.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);

        auto_ptr_XMLCh path("path");
        string s = data_path + "binding/example-metadata.xml";
        auto_ptr_XMLCh file(s.c_str());
        doc->getDocumentElement()->setAttributeNS(nullptr,path.get(),file.get());

        m_metadata = opensaml::SAMLConfig::getConfig().MetadataProviderManager.newPlugin(
            XML_METADATA_PROVIDER,doc->getDocumentElement()
            );
        m_metadata->init();
    }

    void tearDown() {
        delete m_metadata;
        m_metadata=nullptr;
        SAMLSignatureTestBase::tearDown();
    }

    void testEncryptedAssertion() {
        auto_ptr_XMLCh issuer("issuer");
        auto_ptr_XMLCh issueInstant("1970-01-02T01:01:02.100Z");
        auto_ptr_XMLCh id("ident");
        auto_ptr_XMLCh method("method");
        auto_ptr_XMLCh nameid("John Doe");
        
        Issuer* is=IssuerBuilder::buildIssuer();
        is->setName(issuer.get());

        NameID* n=NameIDBuilder::buildNameID();
        n->setName(nameid.get());        
        Subject* subject=SubjectBuilder::buildSubject();
        subject->setNameID(n);

        AuthnStatement* statement=AuthnStatementBuilder::buildAuthnStatement();
        statement->setAuthnInstant(issueInstant.get());

        AuthnContext* ac=AuthnContextBuilder::buildAuthnContext();
        AuthnContextClassRef* acc=AuthnContextClassRefBuilder::buildAuthnContextClassRef();
        acc->setReference(method.get());
        ac->setAuthnContextClassRef(acc);
        statement->setAuthnContext(ac);
        
        auto_ptr<Assertion> assertion(AssertionBuilder::buildAssertion());
        assertion->setID(id.get());
        assertion->setIssueInstant(issueInstant.get());
        assertion->setIssuer(is);
        assertion->setSubject(subject);
        assertion->getAuthnStatements().push_back(statement);

        // Append a Signature.
        Signature* sig=SignatureBuilder::buildSignature();
        assertion->setSignature(sig);

        // Sign while marshalling.
        vector<Signature*> sigs(1,sig);
        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        Locker locker(m_resolver);
        const Credential* cred = m_resolver->resolve(&cc);
        TSM_ASSERT("Retrieved credential was null", cred!=nullptr);

        DOMElement* rootElement = nullptr;
        try {
            rootElement=assertion->marshall((DOMDocument*)nullptr,&sigs,cred);
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
        
        // Now encrypt this puppy to the SP role in the example metadata.
        auto_ptr<EncryptedAssertion> encrypted(EncryptedAssertionBuilder::buildEncryptedAssertion());
        Locker mlocker(m_metadata);
        MetadataProvider::Criteria mc("https://sp.example.org/", &SPSSODescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS);
        pair<const EntityDescriptor*,const RoleDescriptor*> sp = m_metadata->getEntityDescriptor(mc);
        TSM_ASSERT("No metadata for recipient.", sp.first!=nullptr); 
        TSM_ASSERT("No SP role for recipient.", sp.second!=nullptr);
        MetadataCredentialCriteria mcc(*sp.second);
        vector< pair<const MetadataProvider*,MetadataCredentialCriteria*> > recipients(
            1, pair<const MetadataProvider*,MetadataCredentialCriteria*>(m_metadata, &mcc)
            );
#ifdef XSEC_OPENSSL_HAVE_GCM
        encrypted->encrypt(*assertion.get(), recipients, false, DSIGConstants::s_unicodeStrURIAES256_GCM);
#else
        encrypted->encrypt(*assertion.get(), recipients);
#endif

        // Roundtrip it.
        string buf;
        XMLHelper::serialize(encrypted->marshall(), buf);
        //TS_TRACE(buf.c_str());
        istringstream in(buf);
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        
        // Unpack, then decypt with our key.
        auto_ptr<EncryptedAssertion> encrypted2(dynamic_cast<EncryptedAssertion*>(b->buildFromDocument(doc)));
        auto_ptr<Assertion> assertion2(dynamic_cast<Assertion*>(encrypted2->decrypt(*m_resolver, sp.first->getEntityID())));
        assertEquals("Unmarshalled assertion does not match", expectedChildElementsDOM, assertion2.get(), false);
        
        // And check the signature.
        try {
            opensaml::SignatureProfileValidator spv;
            SignatureValidator sv(cred);
            spv.validate(dynamic_cast<Assertion*>(assertion2.get())->getSignature());
            sv.validate(dynamic_cast<Assertion*>(assertion2.get())->getSignature());
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
    }

};
