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

#include "internal.h"

#include <sstream>
#include <saml/signature/SignatureProfileValidator.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/signature/SignatureValidator.h>

using namespace xmlsignature;

class SAMLSignatureTestBase : public SAMLObjectBaseTestCase {
protected:
    scoped_ptr<CredentialResolver> m_resolver;
public:
    void setUp() {
        SAMLObjectBaseTestCase::setUp();
        string config = data_path + "FilesystemCredentialResolver.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);
        m_resolver.reset(
            XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
                FILESYSTEM_CREDENTIAL_RESOLVER, doc->getDocumentElement(), false
                )
            );
    }

    void tearDown() {
        m_resolver.reset(nullptr);
        SAMLObjectBaseTestCase::tearDown();
    }
};
