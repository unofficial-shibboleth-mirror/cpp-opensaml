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
#include <fstream>
#include <cxxtest/GlobalFixture.h>
#include <saml/SAMLConfig.h>
#include <saml/binding/ArtifactMap.h>
#include <xmltooling/util/ReplayCache.h>
#include <xmltooling/util/TemplateEngine.h>

//#define SAML_LEAKCHECK

std::string data_path = "../samltest/data/";

class SAMLFixture : public CxxTest::GlobalFixture
{
public:
    bool setUpWorld() {
        XMLToolingConfig::getConfig().log_config();
        if (!SAMLConfig::getConfig().init())
            return false;
        XMLToolingConfig::getConfig().setReplayCache(new ReplayCache());
        XMLToolingConfig::getConfig().setTemplateEngine(new TemplateEngine());
        SAMLConfig::getConfig().setArtifactMap(new ArtifactMap());

        if (getenv("SAMLTEST_DATA"))
            data_path=std::string(getenv("SAMLTEST_DATA")) + "/";
        //std::string catpath=data_path + "catalog.xml";
        //auto_ptr_XMLCh temp(catpath.c_str());
        //return XMLToolingConfig::getConfig().getValidatingParser().loadCatalog(temp.get());
        return true;
    }
    bool tearDownWorld() {
        SAMLConfig::getConfig().term();
#if defined(_MSC_VER ) && defined(SAML_LEAKCHECK)
       _CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
       _CrtSetReportFile( _CRT_WARN, _CRTDBG_FILE_STDOUT );
       _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE );
       _CrtSetReportFile( _CRT_ERROR, _CRTDBG_FILE_STDOUT );
       _CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
       _CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDOUT );
       _CrtDumpMemoryLeaks();
#endif
        return true;
    }
    //bool setUp() { printf( "</test>" ); return true; }
    //bool tearDown() { printf( "</test>" ); return true; }
};

static SAMLFixture globalFixture;

class GlobalTest : public CxxTest::TestSuite
{
public:
    void testGlobal() {
    }
};
