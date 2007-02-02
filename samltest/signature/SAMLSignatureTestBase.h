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

#include "internal.h"
#include <saml/signature/SignatureProfileValidator.h>

#include <xmltooling/signature/CredentialResolver.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/SignatureValidator.h>

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

class SAMLSignatureTestBase : public SAMLObjectBaseTestCase {
protected:
    CredentialResolver* m_resolver;
public:
    void setUp() {
        m_resolver=NULL;
        SAMLObjectBaseTestCase::setUp();
        string config = data_path + "FilesystemCredentialResolver.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);
        m_resolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
            FILESYSTEM_CREDENTIAL_RESOLVER,doc->getDocumentElement()
            );
    }

    void tearDown() {
        delete m_resolver;
        SAMLObjectBaseTestCase::tearDown();
    }
};
