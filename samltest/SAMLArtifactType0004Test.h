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
#include <saml/SAMLConfig.h>
#include <saml/saml2/binding/SAML2ArtifactType0004.h>

using namespace opensaml::saml2p;
using namespace opensaml;
using namespace std;

class SAMLArtifactType0004Test : public CxxTest::TestSuite
{
public:
    string providerIdStr;

    void setUp() {
        providerIdStr = "https://idp.org/SAML";
    }
    
    void testSAMLArtifactType0004(void) {
        string sourceId = SAMLConfig::getConfig().hashSHA1(providerIdStr.c_str());
        auto_ptr<SAML2ArtifactType0004> artifact(new SAML2ArtifactType0004(sourceId,666));
        auto_ptr<SAML2Artifact> tempArtifact(dynamic_cast<SAML2Artifact*>(SAMLArtifact::parse(artifact->encode().c_str())));
        
        TS_ASSERT_EQUALS(artifact->getSource(),tempArtifact->getSource());
        TS_ASSERT_EQUALS(artifact->getEndpointIndex(),tempArtifact->getEndpointIndex());
        TS_ASSERT_EQUALS(artifact->getMessageHandle(),tempArtifact->getMessageHandle());
        
        TS_ASSERT_THROWS(auto_ptr<SAML2Artifact> bogus1(new SAML2ArtifactType0004(sourceId, 100000)), ArtifactException);
        TS_ASSERT_THROWS(auto_ptr<SAML2Artifact> bogus2(new SAML2ArtifactType0004(sourceId, 666, artifact->getMessageHandle() + artifact->getMessageHandle())), ArtifactException);
    }
};
