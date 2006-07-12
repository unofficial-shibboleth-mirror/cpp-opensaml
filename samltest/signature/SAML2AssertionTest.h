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

#include "signature/SAMLSignatureTestBase.h"
#include <saml/saml2/core/Assertions.h>

#include <fstream>

using namespace opensaml::saml2;

class SAML2AssertionTest : public CxxTest::TestSuite, public SAMLSignatureTestBase {
public:
    void setUp() {
        childElementsFile  = data_path + "signature/SAML2Assertion.xml";
        SAMLSignatureTestBase::setUp();
    }

    void tearDown() {
        SAMLSignatureTestBase::tearDown();
    }

    void testSignature() {
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
        sig->setSigningKey(m_key->clone());

        // Build KeyInfo.
        KeyInfo* keyInfo=KeyInfoBuilder::buildKeyInfo();
        X509Data* x509Data=X509DataBuilder::buildX509Data();
        keyInfo->getX509Datas().push_back(x509Data);
        for_each(m_certs.begin(),m_certs.end(),bind1st(_addcert(),x509Data));
        sig->setKeyInfo(keyInfo);

        // Sign while marshalling.
        vector<Signature*> sigs(1,sig);
        DOMElement* rootElement = NULL;
        try {
            rootElement=assertion->marshall((DOMDocument*)NULL,&sigs);
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
        
        string buf;
        XMLHelper::serialize(rootElement, buf);
        istringstream in(buf);
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        
        assertEquals(expectedChildElementsDOM, b->buildFromDocument(doc));
        
        try {
            SignatureProfileValidator spv;
            SignatureValidator sv(new KeyResolver(m_key->clone()));
            spv.validate(assertion->getSignature());
            sv.validate(assertion->getSignature());
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
    }

};
