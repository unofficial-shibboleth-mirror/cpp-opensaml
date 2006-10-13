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
#include "saml/binding/ArtifactMap.h"
#include <saml/saml2/binding/SAML2ArtifactType0004.h>
#include <saml/saml2/core/Protocols.h>

using namespace opensaml::saml2p;
using namespace opensaml;
using namespace std;

class ArtifactMapTest : public CxxTest::TestSuite
{
public:
    string providerIdStr;
    string handle;
    void setUp() {
        if (handle.empty()) {
            providerIdStr = "https://idp.org/SAML";
            SAMLConfig::getConfig().generateRandomBytes(handle,SAML2ArtifactType0004::HANDLE_LENGTH);
        }
    }
    void tearDown() {
    }
    void testArtifactMap(void) {
        auto_ptr<Response> response(ResponseBuilder::buildResponse());

        SAML2ArtifactType0004 artifact(SAMLConfig::getConfig().hashSHA1(providerIdStr.c_str()),666,handle);
        
        ArtifactMap* artifactMap = SAMLConfig::getConfig().getArtifactMap();
        artifactMap->storeContent(response.get(), &artifact, providerIdStr.c_str());
        response.release();

        auto_ptr<XMLObject> xmlObject(artifactMap->retrieveContent(&artifact, providerIdStr.c_str()));
        TSM_ASSERT_THROWS("Artifact resolution improperly succeeded.", artifactMap->retrieveContent(&artifact), BindingException);
        TSM_ASSERT("Mapped content was not a Response.", dynamic_cast<Response*>(xmlObject.get())!=NULL);
    }
};
