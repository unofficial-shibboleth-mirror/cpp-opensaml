/*
 *  Copyright 2001-2006 Internet2
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

#include <cxxtest/TestSuite.h>

#include <fstream>
#include <saml/exceptions.h>
#include <saml/SAMLConfig.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/XMLObject.h>
#include <xmltooling/XMLObjectBuilder.h>

using namespace opensaml;
using namespace xmltooling;
using namespace std;

extern string data_path;

class SAMLObjectBaseTestCase
{
protected:
    /** Location of file containing a single element with NO optional attributes */
    string singleElementFile;

    /** Location of file containing a single element with all optional attributes */
    string singleElementOptionalAttributesFile;

    /** Location of file containing a single element with child elements */
    string childElementsFile;

    /** The expected result of a marshalled single element with no optional attributes */
    DOMDocument* expectedDOM;

    /** The expected result of a marshalled single element with all optional attributes */
    DOMDocument* expectedOptionalAttributesDOM;

    /** The expected result of a marshalled single element with child elements */
    DOMDocument* expectedChildElementsDOM;

    /**
     * Unmarshalls an element file into its SAML XMLObject.
     * 
     * @return the SAML XMLObject from the file
     */
    XMLObject* unmarshallElement(string elementFile) {
        try {
            ParserPool& p=XMLToolingConfig::getConfig().getParser();
            ifstream fs(elementFile.c_str());
            DOMDocument* doc = p.parse(fs);
            const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
            return b->buildFromDocument(doc);
        }
        catch (XMLToolingException& e) {
            TS_TRACE(typeid(e).name());
            TS_TRACE(e.what());
            throw;
        }
    }

    void assertEquals(const char* failMessage, DOMDocument* expectedDOM, XMLObject* xmlObject) {
        DOMElement* generatedDOM = xmlObject->marshall();
        if (!generatedDOM->isEqualNode(expectedDOM->getDocumentElement())) {
            string buf;
            XMLHelper::serialize(generatedDOM, buf);
            TS_TRACE(buf.c_str());
            buf.erase();
            XMLHelper::serialize(expectedDOM->getDocumentElement(), buf);
            TS_TRACE(buf.c_str());
            TSM_ASSERT(failMessage, false);
        }
    }

    void assertEquals(DOMDocument* expectedDOM, XMLObject* xmlObject) {
        assertEquals("Marshalled DOM was not the same as the expected DOM", expectedDOM, xmlObject);
        delete xmlObject;
    }

    void assertEquals(const char* failMessage, const XMLCh* expectedString, const XMLCh* testString) {
        char* buf = NULL;
        if (!XMLString::equals(expectedString, testString)) {
            buf = XMLString::transcode(testString);
            TS_TRACE(buf);
            XMLString::release(&buf);
            buf = XMLString::transcode(expectedString);
            TS_TRACE(buf);
            XMLString::release(&buf);
            TSM_ASSERT(failMessage, false);
        }
    }

public:
    void setUp() {
        ParserPool& p=XMLToolingConfig::getConfig().getParser();
        if (!singleElementFile.empty()) {
            ifstream fs(singleElementFile.c_str());
            expectedDOM = p.parse(fs);
        }

        if (!singleElementOptionalAttributesFile.empty()) {
            ifstream fs(singleElementOptionalAttributesFile.c_str());
            expectedOptionalAttributesDOM = p.parse(fs);
        }

        if (!childElementsFile.empty()) {
            ifstream fs(childElementsFile.c_str());
            expectedChildElementsDOM = p.parse(fs);
        }
    }
    
    void tearDown() {
        if (expectedDOM) expectedDOM->release();
        if (expectedOptionalAttributesDOM) expectedOptionalAttributesDOM->release();
        if (expectedChildElementsDOM) expectedChildElementsDOM->release();
    }
};
