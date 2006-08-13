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

#include <saml/saml1/core/Protocols.h>

#include <fstream>

using namespace opensaml::saml1p;
using namespace opensaml::saml1;

class SAML1RequestTest : public CxxTest::TestSuite, public SAMLSignatureTestBase {
public:
    void setUp() {
        childElementsFile  = data_path + "signature/SAML1Request.xml";
        SAMLSignatureTestBase::setUp();
    }

    void tearDown() {
        SAMLSignatureTestBase::tearDown();
    }

    void testSignature() {
        auto_ptr_XMLCh issueInstant("1970-01-02T01:01:02.100Z");
        auto_ptr_XMLCh id("ident");
        auto_ptr_XMLCh method("method");
        auto_ptr_XMLCh nameid("John Doe");
        
        NameIdentifier* n=NameIdentifierBuilder::buildNameIdentifier();
        n->setName(nameid.get());        
        Subject* subject=SubjectBuilder::buildSubject();
        subject->setNameIdentifier(n);

        AuthenticationQuery* query=AuthenticationQueryBuilder::buildAuthenticationQuery();
        query->setAuthenticationMethod(method.get());
        query->setSubject(subject);
        
        auto_ptr<Request> request(RequestBuilder::buildRequest());
        request->setRequestID(id.get());
        request->setIssueInstant(issueInstant.get());
        request->setAuthenticationQuery(query);

        // Append a Signature.
        Signature* sig=SignatureBuilder::buildSignature();
        request->setSignature(sig);
        Locker locker(m_resolver);
        sig->setSigningKey(m_resolver->getKey());

        // Build KeyInfo.
        KeyInfo* keyInfo=KeyInfoBuilder::buildKeyInfo();
        X509Data* x509Data=X509DataBuilder::buildX509Data();
        keyInfo->getX509Datas().push_back(x509Data);
        for_each(m_resolver->getCertificates().begin(),m_resolver->getCertificates().end(),bind1st(_addcert(),x509Data));
        sig->setKeyInfo(keyInfo);

        // Sign while marshalling.
        vector<Signature*> sigs(1,sig);
        DOMElement* rootElement = NULL;
        try {
            rootElement=request->marshall((DOMDocument*)NULL,&sigs);
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

        auto_ptr<XMLObject> request2(b->buildFromDocument(doc));
        assertEquals("Unmarshalled request does not match", expectedChildElementsDOM, request2.get(), false);
        
        try {
            SignatureProfileValidator spv;
            SignatureValidator sv(new KeyResolver(m_resolver->getKey()));
            spv.validate(dynamic_cast<Request*>(request2.get())->getSignature());
            sv.validate(dynamic_cast<Request*>(request2.get())->getSignature());
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
    }

};
