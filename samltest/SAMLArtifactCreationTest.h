/*
 *  Copyright 2001-2010 Internet2
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
#include <saml/saml1/binding/SAMLArtifactType0001.h>
#include <saml/saml1/binding/SAMLArtifactType0002.h>
#include <saml/saml2/binding/SAML2ArtifactType0004.h>
#include <xmltooling/security/SecurityHelper.h>

using namespace opensaml::saml1p;
using namespace opensaml::saml2p;
using namespace opensaml;
using namespace std;

class SAMLArtifactCreationTest : public CxxTest::TestSuite
{
public:
    string providerIdStr;
    string handle;
    void setUp() {
        if (handle.empty()) {
            providerIdStr = "https://idp.org/SAML";
            SAMLConfig::getConfig().generateRandomBytes(handle,SAMLArtifactType0001::HANDLE_LENGTH);
        }
    }
    void testSAMLArtifactType0001(void) {
        SAMLConfig& conf=SAMLConfig::getConfig();
        string sourceId;
        conf.generateRandomBytes(sourceId,SAMLArtifactType0001::SOURCEID_LENGTH);
        SAMLArtifactType0001 artifact1(sourceId,handle);
        //printResults(artifact1);

        SAMLArtifactType0001 artifact2(
            SecurityHelper::doHash("SHA1", providerIdStr.data(), providerIdStr.length(), false), handle
            );
        //printResults(artifact2,providerIdStr.c_str());
    }

    void testSAMLArtifactType0002(void) {
        SAMLArtifactType0002 artifact(providerIdStr,handle);
        //printResults(artifact,providerIdStr.c_str());
    }

    void testSAMLArtifactType0004(void) {
        SAML2ArtifactType0004 artifact(
            SecurityHelper::doHash("SHA1", providerIdStr.data(), providerIdStr.length(), false), 666, handle
            );
        //printResults(artifact,providerIdStr.c_str());
    }

    void printResults(SAMLArtifact& artifact, const char* str=nullptr) {
        // print heading:
        cout << "Artifact Type " << SAMLArtifact::toHex(artifact.getTypeCode());
        cout << " (size = " << artifact.getBytes().size() << ")" << endl;
    
        // print URI:
        if (str) { 
          cout << "URI:     " << str << endl; 
        }
        else {
          cout << "URI:     NONE" << endl; 
        }
    
        // print hex-encoded artifact:
        cout << "Hex:     " << SAMLArtifact::toHex(artifact.getBytes()) << endl;
    
        // print base64-encoded artifact:
        cout << "Base64:  " << artifact.encode() << endl;
    
        // print ruler:
        cout <<  "         ----------------------------------------------------------------------" << endl;
        cout <<  "         1234567890123456789012345678901234567890123456789012345678901234567890" << endl;
        cout <<  "                  1         2         3         4         5         6         7" << endl;
        cout <<  "         ----------------------------------------------------------------------" << endl;
    }
};
