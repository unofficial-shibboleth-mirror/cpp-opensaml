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

#ifdef WIN32
# define _CRT_SECURE_NO_DEPRECATE 1
# define _CRT_NONSTDC_NO_DEPRECATE 1
#endif

#include <cxxtest/TestSuite.h>

#include <fstream>
#include <saml/exceptions.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/XMLObject.h>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/validation/Validator.h>

using namespace xmltooling;
using namespace xercesc;
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

    void assertEquals(const char* failMessage, DOMDocument* expectedDOM, XMLObject* xmlObject, bool canMarshall=true) {
        DOMElement* generatedDOM = xmlObject->getDOM();
        if (!generatedDOM) {
            if (!canMarshall) {
                TSM_ASSERT("DOM not available", false);
            }
            else {
                generatedDOM = xmlObject->marshall();
            }
        }
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

    void assertEquals(DOMDocument* expectedDOM, XMLObject* xmlObject, bool canMarshall=true) {
        assertEquals("Marshalled DOM was not the same as the expected DOM", expectedDOM, xmlObject, canMarshall);
        delete xmlObject;
    }

    void assertEquals(const char* failMessage, const XMLCh* expectedString, const XMLCh* testString) {
        char* buf = NULL;
        if (!XMLString::equals(expectedString, testString)) {
            buf = XMLString::transcode(testString);
            TS_TRACE(buf ? buf : "(NULL)");
            XMLString::release(&buf);
            buf = XMLString::transcode(expectedString);
            TS_TRACE(buf ? buf : "(NULL)");
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

class SAMLObjectValidatorBaseTestCase : virtual public SAMLObjectBaseTestCase {

    public:
        SAMLObjectValidatorBaseTestCase() : target(NULL), targetQName(NULL), builder(NULL), validator(NULL) {}

        virtual ~SAMLObjectValidatorBaseTestCase() {
            delete validator;
        }

    protected: 
        /** The primary XMLObject which will be the target of a given test run */
        XMLObject* target;

        /** QName of the object to be tested */
        xmltooling::QName targetQName;

        /** Builder for XMLObjects of type targetQName */
        const XMLObjectBuilder* builder;

        /** Validator for the type corresponding to the test target */
        Validator* validator;

        /** Subclasses should override to populate required elements and attributes */
        virtual void populateRequiredData() { }

        /**
         * Asserts that the validation of default test XMLObject target 
         * was successful, as expected.
         * 
         * @param message
         */
        void assertValidationPass(const char* message) {
            assertValidationPass(message, target);
        }

        /**
         * Asserts that the validation of the specified XMLObject target 
         * was successful, as expected.
         * 
         * @param message
         * @param validateTarget
         */
        void assertValidationPass(const char* message, XMLObject* validateTarget) {
            try {
                validator->validate(validateTarget);
            } catch (ValidationException &e) {
                TS_TRACE(message);
                TS_TRACE("Expected success, but validation failure raised following ValidationException: ");
                TS_FAIL(e.getMessage());
            }
        }

        /**
         * Asserts that the validation of the default test XMLObject target 
         * failed, as expected.
         * 
         * @param message
         */
        void assertValidationFail(const char* message) {
            assertValidationFail(message, target);
        }

        /**
         * Asserts that the validation of the specified XMLObject target 
         * failed, as expected.
         * 
         * @param message
         * @param validateTarget
         */
        void assertValidationFail(const char* message, XMLObject* validateTarget) {
            try {
                validator->validate(validateTarget);
                TS_TRACE(message);
                TS_FAIL("Validation success, expected failure to raise ValidationException");
            } catch (ValidationException&) {
            }
        }

        /**
         * Build an XMLObject based on the specified QName
         * 
         * @param targetQName QName of the type of object to build
         * @returns new XMLObject of type targetQName
         */
        XMLObject* buildXMLObject(xmltooling::QName &targetQName) {
            // Create the builder on the first request only, for efficiency
            if (builder == NULL) {
                builder = XMLObjectBuilder::getBuilder(targetQName);
                TSM_ASSERT("Unable to retrieve builder for object QName: " + targetQName.toString(), builder!=NULL);
            }
            return builder->buildObject(targetQName.getNamespaceURI(), targetQName.getLocalPart(), targetQName.getPrefix());

        }

    public:

        void setUp() {
            SAMLObjectBaseTestCase::setUp();

            TSM_ASSERT("targetQName was empty", targetQName.hasLocalPart());

            TSM_ASSERT("validator was null", validator!=NULL);

            target = buildXMLObject(targetQName);
            TSM_ASSERT("XMLObject target was NULL", target!=NULL);
            populateRequiredData();
        }

        void tearDown() {
            delete target;
            target=NULL;
            SAMLObjectBaseTestCase::tearDown();
        }

};

