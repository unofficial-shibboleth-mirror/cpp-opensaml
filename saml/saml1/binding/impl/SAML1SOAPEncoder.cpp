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

/**
 * SAML1SOAPEncoder.cpp
 * 
 * SAML 1.x SOAP binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/HTTPResponse.h"
#include "saml1/binding/SAML1SOAPEncoder.h"
#include "saml1/core/Protocols.h"

#include <sstream>
#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>
#include <xmltooling/soap/SOAP.h>

using namespace opensaml::saml1p;
using namespace opensaml;
using namespace xmlsignature;
using namespace soap11;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml1p {              
        MessageEncoder* SAML_DLLLOCAL SAML1SOAPEncoderFactory(const DOMElement* const & e)
        {
            return new SAML1SOAPEncoder(e);
        }
    };
};

SAML1SOAPEncoder::SAML1SOAPEncoder(const DOMElement* e) {}

long SAML1SOAPEncoder::encode(
    GenericResponse& genericResponse,
    XMLObject* xmlObject,
    const char* destination,
    const char* recipientID,
    const char* relayState,
    const CredentialResolver* credResolver,
    const XMLCh* sigAlgorithm
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("encode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML1SOAP");

    log.debug("validating input");
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");

    genericResponse.setContentType("text/xml");

    DOMElement* rootElement = NULL;
    Response* response = dynamic_cast<Response*>(xmlObject);
    if (response) {
        try {
            Envelope* env = EnvelopeBuilder::buildEnvelope();
            Body* body = BodyBuilder::buildBody();
            env->setBody(body);
            body->getXMLObjects().push_back(response);
            if (credResolver ) {
                if (response->getSignature()) {
                    log.debug("response already signed, skipping signature operation");
                    rootElement = env->marshall();
                }
                else {
                    log.debug("signing and marshalling the response");
        
                    // Build a Signature.
                    Signature* sig = buildSignature(credResolver, sigAlgorithm);
                    response->setSignature(sig);
            
                    // Sign response while marshalling.
                    vector<Signature*> sigs(1,sig);
                    rootElement = env->marshall((DOMDocument*)NULL,&sigs);
                }
            }
            else {
                log.debug("marshalling the response");
                rootElement = env->marshall();
            }
            
            string xmlbuf;
            XMLHelper::serialize(rootElement, xmlbuf);
            istringstream s(xmlbuf);
            log.debug("sending serialized response");
            long ret = genericResponse.sendResponse(s);
        
            // Cleanup by destroying XML.
            delete env;
            return ret;
        }
        catch (XMLToolingException&) {
            // A bit weird...we have to "revert" things so that the response is isolated
            // so the caller can free it.
            if (response->getParent()) {
                response->getParent()->detach();
                response->detach();
            }
            throw;
        }
    }

    Fault* fault = dynamic_cast<Fault*>(xmlObject);
    if (fault) {
        try {
            log.debug("building Envelope and marshalling Fault");
            Envelope* env = EnvelopeBuilder::buildEnvelope();
            Body* body = BodyBuilder::buildBody();
            env->setBody(body);
            body->getXMLObjects().push_back(fault);
            rootElement = env->marshall();
    
            string xmlbuf;
            XMLHelper::serialize(rootElement, xmlbuf);
            istringstream s(xmlbuf);
            log.debug("sending serialized fault");
            long ret = genericResponse.sendError(s);
        
            // Cleanup by destroying XML.
            delete env;
            return ret;
        }
        catch (XMLToolingException&) {
            // A bit weird...we have to "revert" things so that the fault is isolated
            // so the caller can free it.
            if (fault->getParent()) {
                fault->getParent()->detach();
                fault->detach();
            }
            throw;
        }
    }

    Envelope* env = dynamic_cast<Envelope*>(xmlObject);
    if (env) {
        log.debug("marshalling envelope");
        rootElement = env->marshall();

        bool error =
            (env->getBody() &&
                env->getBody()->hasChildren() &&
                    dynamic_cast<Fault*>(env->getBody()->getXMLObjects().front()));

        string xmlbuf;
        XMLHelper::serialize(rootElement, xmlbuf);
        istringstream s(xmlbuf);
        log.debug("sending serialized envelope");
        long ret = error ? genericResponse.sendError(s) : genericResponse.sendResponse(s);
    
        // Cleanup by destroying XML.
        delete env;
        return ret;
    }

    throw BindingException("XML content for SAML 1.x SOAP Encoder must be a SAML 1.x <Response> or SOAP Fault/Envelope.");
}
