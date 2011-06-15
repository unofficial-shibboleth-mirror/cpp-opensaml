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
#include <saml/SAMLConfig.h>
#include <saml/saml1/binding/SAMLArtifactType0001.h>
#include <xmltooling/security/SecurityHelper.h>

using namespace opensaml::saml1p;
using namespace opensaml;
using namespace std;

class SAMLArtifactType0001Test : public CxxTest::TestSuite
{
public:
    string providerIdStr;

    void setUp() {
        providerIdStr = "https://idp.org/SAML";
    }
    
    void testSAMLArtifactType0001(void) {
        string sourceId = SecurityHelper::doHash("SHA1", providerIdStr.data(), providerIdStr.length(), false);
        auto_ptr<SAMLArtifactType0001> artifact(new SAMLArtifactType0001(sourceId));
        auto_ptr<SAMLArtifact> tempArtifact(SAMLArtifact::parse(artifact->encode().c_str()));
        
        TS_ASSERT_EQUALS(artifact->getSource(),tempArtifact->getSource());
        TS_ASSERT_EQUALS(artifact->getMessageHandle(),tempArtifact->getMessageHandle());
        
        TS_ASSERT_THROWS(auto_ptr<SAMLArtifact> bogus1(new SAMLArtifactType0001(sourceId + sourceId)), ArtifactException);
        TS_ASSERT_THROWS(auto_ptr<SAMLArtifact> bogus2(new SAMLArtifactType0001(sourceId, artifact->getMessageHandle() + artifact->getMessageHandle())), ArtifactException);
    }
};
