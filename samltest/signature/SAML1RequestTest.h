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
#include <saml/saml1/core/Protocols.h>
#include <saml/signature/SignatureProfileValidator.h>
#include <xmltooling/signature/SignatureValidator.h>


#include <fstream>
#include <openssl/pem.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/framework/XSECException.hpp>

using namespace opensaml::saml1p;
using namespace opensaml::saml1;
using namespace xmlsignature;

class _addcert : public std::binary_function<X509Data*,XSECCryptoX509*,void> {
public:
    void operator()(X509Data* bag, XSECCryptoX509* cert) const {
        safeBuffer& buf=cert->getDEREncodingSB();
        X509Certificate* x=X509CertificateBuilder::buildX509Certificate();
        x->setValue(buf.sbStrToXMLCh());
        bag->getX509Certificates().push_back(x);
    }
};

class SAML1RequestTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XSECCryptoKey* m_key;
    vector<XSECCryptoX509*> m_certs;
public:
    void setUp() {
        childElementsFile  = data_path + "signature/SAML1Request.xml";
        SAMLObjectBaseTestCase::setUp();
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

    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
        delete m_key;
        for_each(m_certs.begin(),m_certs.end(),xmltooling::cleanup<XSECCryptoX509>());
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

        assertEquals(expectedChildElementsDOM, b->buildFromDocument(doc));
        
        try {
            request->getSignature()->registerValidator(new SignatureProfileValidator());
            request->getSignature()->registerValidator(new SignatureValidator(m_key->clone()));
            request->getSignature()->validate(true);
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
    }

};
