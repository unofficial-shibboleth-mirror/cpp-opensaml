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

#include "internal.h"
#include <saml/saml1/core/Assertions.h>
#include <saml/signature/SigningContext.h>
#include <saml/signature/VerifyingContext.h>

using namespace opensaml::saml1;

#include <fstream>
#include <openssl/pem.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xmltooling/signature/Signature.h>

class TestContext : public virtual CredentialResolver, public SigningContext, public VerifyingContext
{
    vector<XSECCryptoX509*> m_certs;
    OpenSSLCryptoKeyRSA* m_key;
public:
    TestContext(const XMLCh* uri) : VerifyingContext(uri), SigningContext(uri,*this), m_key(NULL) {
        string keypath=data_path + "key.pem";
        BIO* in=BIO_new(BIO_s_file_internal());
        if (in && BIO_read_filename(in,keypath.c_str())>0) {
            EVP_PKEY* pkey=PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
            if (pkey) {
                m_key=new OpenSSLCryptoKeyRSA(pkey);
                EVP_PKEY_free(pkey);
            }
        }
        if (in) BIO_free(in);
        TS_ASSERT(m_key!=NULL);

        string certpath=data_path + "cert.pem";
        in=BIO_new(BIO_s_file_internal());
        if (in && BIO_read_filename(in,certpath.c_str())>0) {
            X509* x=NULL;
            while (x=PEM_read_bio_X509(in,NULL,NULL,NULL)) {
                m_certs.push_back(new OpenSSLCryptoX509(x));
                X509_free(x);
            }
        }
        if (in) BIO_free(in);
        TS_ASSERT(m_certs.size()>0);
    }
    
    virtual ~TestContext() {
        delete m_key;
        for_each(m_certs.begin(),m_certs.end(),xmltooling::cleanup<XSECCryptoX509>());
    }
    
    void verifySignature(DSIGSignature* sig) const {
        VerifyingContext::verifySignature(sig);
        sig->setSigningKey(NULL);
        XSECKeyInfoResolverDefault resolver;
        sig->setKeyInfoResolver(&resolver);
        sig->verify();
    }

    xmlsignature::KeyInfo* getKeyInfo() { return NULL; }
    const char* getId() const { return "test"; }
    const vector<XSECCryptoX509*>* getX509Certificates() { return &m_certs; }
    XSECCryptoKey* getPublicKey() { return m_key; }
    XSECCryptoKey* getPrivateKey() { return m_key; }
    Lockable& lock() { return *this; }
    void unlock() {}
};

class SAML1AssertionTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
public:
    void setUp() {
        childElementsFile  = data_path + "signature/SAML1Assertion.xml";
        SAMLObjectBaseTestCase::setUp();
    }

    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSignature() {
        auto_ptr_XMLCh issuer("issuer");
        auto_ptr_XMLCh issueInstant("1970-01-02T01:01:02.100Z");
        auto_ptr_XMLCh id("ident");
        auto_ptr_XMLCh method("method");
        auto_ptr_XMLCh nameid("John Doe");
        
        NameIdentifier* n=NameIdentifierBuilder::buildNameIdentifier();
        n->setName(nameid.get());        
        Subject* subject=SubjectBuilder::buildSubject();
        subject->setNameIdentifier(n);

        AuthenticationStatement* statement=AuthenticationStatementBuilder::buildAuthenticationStatement();
        statement->setAuthenticationInstant(issueInstant.get());
        statement->setAuthenticationMethod(method.get());
        statement->setSubject(subject);
        
        auto_ptr<Assertion> assertion(AssertionBuilder::buildAssertion());
        assertion->setAssertionID(id.get());
        assertion->setIssueInstant(issueInstant.get());
        assertion->setIssuer(issuer.get());
        assertion->getAuthenticationStatements().push_back(statement);

        // Append a Signature.
        xmlsignature::Signature* sig=xmlsignature::SignatureBuilder::newSignature();
        assertion->setSignature(sig);
        
        // Signing context for the assertion.
        TestContext tc(id.get());
        MarshallingContext mctx(sig,&tc);
        DOMElement* rootElement = assertion->marshall((DOMDocument*)NULL,&mctx);
        
        string buf;
        XMLHelper::serialize(rootElement, buf);
        istringstream in(buf);
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        
        assertEquals(expectedChildElementsDOM, b->buildFromDocument(doc));
        
        try {
            assertion->getSignature()->verify(tc);
        }
        catch (xmlsignature::SignatureException& e) {
            TS_TRACE(e.what());
            throw;
        }
    }

};
