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

/**
 * SAML2SOAPEncoder.cpp
 * 
 * SAML 2.0 SOAP binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/MessageEncoder.h"
#include "signature/ContentReference.h"
#include "saml2/core/Protocols.h"

#include <sstream>
#include <log4cpp/Category.hh>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/soap/SOAP.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace soap11;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        class SAML_DLLLOCAL SAML2SOAPEncoder : public MessageEncoder
        {
        public:
            SAML2SOAPEncoder(const DOMElement* e);
            virtual ~SAML2SOAPEncoder() {}
            
            long encode(
                GenericResponse& genericResponse,
                XMLObject* xmlObject,
                const char* destination,
                const EntityDescriptor* recipient=NULL,
                const char* relayState=NULL,
                const ArtifactGenerator* artifactGenerator=NULL,
                const Credential* credential=NULL,
                const XMLCh* signatureAlg=NULL,
                const XMLCh* digestAlg=NULL
                ) const;
        };

        MessageEncoder* SAML_DLLLOCAL SAML2SOAPEncoderFactory(const DOMElement* const & e)
        {
            return new SAML2SOAPEncoder(e);
        }
    };
};

SAML2SOAPEncoder::SAML2SOAPEncoder(const DOMElement* e) {}

long SAML2SOAPEncoder::encode(
    GenericResponse& genericResponse,
    XMLObject* xmlObject,
    const char* destination,
    const EntityDescriptor* recipient,
    const char* relayState,
    const ArtifactGenerator* artifactGenerator,
    const Credential* credential,
    const XMLCh* signatureAlg,
    const XMLCh* digestAlg
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("encode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML2SOAP");

    log.debug("validating input");
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");

    genericResponse.setContentType("text/xml");
    HTTPResponse* httpResponse = dynamic_cast<HTTPResponse*>(&genericResponse);
    if (httpResponse) {
        httpResponse->setResponseHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
        httpResponse->setResponseHeader("Pragma", "no-cache");
    }

    DOMElement* rootElement = NULL;
    StatusResponseType* response = dynamic_cast<StatusResponseType*>(xmlObject);
    if (response) {
        try {
            Envelope* env = EnvelopeBuilder::buildEnvelope();
            Body* body = BodyBuilder::buildBody();
            env->setBody(body);
            body->getUnknownXMLObjects().push_back(response);
            if (credential) {
                if (response->getSignature()) {
                    log.debug("response already signed, skipping signature operation");
                    rootElement = env->marshall();
                }
                else {
                    log.debug("signing and marshalling the response");
        
                    // Build a Signature.
                    Signature* sig = SignatureBuilder::buildSignature();
                    response->setSignature(sig);    
                    if (signatureAlg)
                        sig->setSignatureAlgorithm(signatureAlg);
                    if (digestAlg) {
                        opensaml::ContentReference* cr = dynamic_cast<opensaml::ContentReference*>(sig->getContentReference());
                        if (cr)
                            cr->setDigestAlgorithm(digestAlg);
                    }
            
                    // Sign response while marshalling.
                    vector<Signature*> sigs(1,sig);
                    rootElement = env->marshall((DOMDocument*)NULL,&sigs,credential);
                }
            }
            else {
                log.debug("marshalling the response");
                rootElement = env->marshall();
            }
            
            stringstream s;
            s << *rootElement;
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
            body->getUnknownXMLObjects().push_back(fault);
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
                    dynamic_cast<Fault*>(env->getBody()->getUnknownXMLObjects().front()));

        string xmlbuf;
        XMLHelper::serialize(rootElement, xmlbuf);
        istringstream s(xmlbuf);
        log.debug("sending serialized envelope");
        long ret = error ? genericResponse.sendError(s) : genericResponse.sendResponse(s);
    
        // Cleanup by destroying XML.
        delete env;
        return ret;
    }

    throw BindingException("XML content for SAML 2.0 SOAP Encoder must be a SAML 2.0 response or SOAP Fault/Envelope.");
}
