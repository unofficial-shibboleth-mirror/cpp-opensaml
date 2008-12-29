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
 * SAML2ECPEncoder.cpp
 * 
 * SAML 2.0 ECP profile message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/MessageEncoder.h"
#include "signature/ContentReference.h"
#include "saml1/core/Protocols.h"
#include "saml2/core/Protocols.h"

#include <sstream>
#include <xmltooling/logging.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/soap/SOAP.h>

using namespace samlconstants;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlconstants;
using namespace xmlsignature;
using namespace soap11;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        
        static const XMLCh ProviderName[] = UNICODE_LITERAL_12(P,r,o,v,i,d,e,r,N,a,m,e);

        class SAML_DLLLOCAL SAML2ECPEncoder : public MessageEncoder
        {
        public:
            SAML2ECPEncoder(const DOMElement* e, const XMLCh* ns) : m_actor("http://schemas.xmlsoap.org/soap/actor/next"),
                    m_providerName(e ? e->getAttributeNS(ns, ProviderName) : NULL), m_idpList(NULL) {
                DOMElement* child = e ? XMLHelper::getFirstChildElement(e, SAML20P_NS, IDPList::LOCAL_NAME) : NULL;
                if (child)
                    m_idpList = dynamic_cast<IDPList*>(XMLObjectBuilder::buildOneFromElement(child));
            }
            virtual ~SAML2ECPEncoder() {
                delete m_idpList;
            }

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
            
        private:
            auto_ptr_XMLCh m_actor;
            const XMLCh* m_providerName;
            IDPList* m_idpList;
            AnyElementBuilder m_anyBuilder;
        };

        MessageEncoder* SAML_DLLLOCAL SAML2ECPEncoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
        {
            return new SAML2ECPEncoder(p.first, p.second);
        }
    };
};

long SAML2ECPEncoder::encode(
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
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML2ECP");

    log.debug("validating input");
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");

    Response* response = NULL;
    AuthnRequest* request = dynamic_cast<AuthnRequest*>(xmlObject);
    if (!request) {
        response = dynamic_cast<Response*>(xmlObject);
        if (!response)
            throw BindingException("XML content for SAML 2.0 ECP Encoder must be a SAML 2.0 AuthnRequest or Response.");
    }
    
    if (request && !request->getAssertionConsumerServiceURL())
        throw BindingException("AuthnRequest must carry an AssertionConsumerServiceURL by value.");
    else if (response && !response->getDestination())
        throw BindingException("Response must carry a Destination attribute.");
    
    // PAOS request leg is a custom MIME type, SOAP response leg is just text/xml.
    genericResponse.setContentType(request ? "application/vnd.paos+xml" : "text/xml");
    HTTPResponse* httpResponse = dynamic_cast<HTTPResponse*>(&genericResponse);
    if (httpResponse) {
        httpResponse->setResponseHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
        httpResponse->setResponseHeader("Pragma", "no-cache");
    }

    // Wrap it in a SOAP envelope.
    Envelope* env = EnvelopeBuilder::buildEnvelope();
    Header* header = HeaderBuilder::buildHeader();
    env->setHeader(header);
    Body* body = BodyBuilder::buildBody();
    env->setBody(body);
    body->getUnknownXMLObjects().push_back(xmlObject);

    ElementProxy* hdrblock;
    xmltooling::QName qMU(SOAP11ENV_NS, Header::MUSTUNDERSTAND_ATTRIB_NAME, SOAP11ENV_PREFIX);
    xmltooling::QName qActor(SOAP11ENV_NS, Header::ACTOR_ATTRIB_NAME, SOAP11ENV_PREFIX);
    
    if (request) {
        // Create paos:Request header.
        static const XMLCh service[] = UNICODE_LITERAL_7(s,e,r,v,i,c,e);
        static const XMLCh responseConsumerURL[] = UNICODE_LITERAL_19(r,e,s,p,o,n,s,e,C,o,n,s,u,m,e,r,U,R,L);
        hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(PAOS_NS, saml1p::Request::LOCAL_NAME, PAOS_PREFIX));
        hdrblock->setAttribute(qMU, XML_ONE);
        hdrblock->setAttribute(qActor, m_actor.get());
        hdrblock->setAttribute(xmltooling::QName(NULL, service), SAML20ECP_NS);
        hdrblock->setAttribute(xmltooling::QName(NULL, responseConsumerURL), request->getAssertionConsumerServiceURL());
        header->getUnknownXMLObjects().push_back(hdrblock);

        // Create ecp:Request header.
        static const XMLCh IsPassive[] = UNICODE_LITERAL_9(I,s,P,a,s,s,i,v,e);
        hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(SAML20ECP_NS, saml1p::Request::LOCAL_NAME, SAML20ECP_PREFIX));
        hdrblock->setAttribute(qMU, XML_ONE);
        hdrblock->setAttribute(qActor, m_actor.get());
        if (!request->IsPassive())
            hdrblock->setAttribute(xmltooling::QName(NULL,IsPassive), XML_ZERO);
        if (m_providerName)
            hdrblock->setAttribute(xmltooling::QName(NULL,ProviderName), m_providerName);
        hdrblock->getUnknownXMLObjects().push_back(request->getIssuer()->clone());
        if (request->getScoping() && request->getScoping()->getIDPList())
            hdrblock->getUnknownXMLObjects().push_back(request->getScoping()->getIDPList()->clone());
        else if (m_idpList)
            hdrblock->getUnknownXMLObjects().push_back(m_idpList->clone());
        header->getUnknownXMLObjects().push_back(hdrblock);
    }
    else {
        // Create ecp:Response header.
        hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(SAML20ECP_NS, Response::LOCAL_NAME, SAML20ECP_PREFIX));
        hdrblock->setAttribute(qMU, XML_ONE);
        hdrblock->setAttribute(qActor, m_actor.get());
        hdrblock->setAttribute(xmltooling::QName(NULL,AuthnRequest::ASSERTIONCONSUMERSERVICEURL_ATTRIB_NAME), response->getDestination());
        header->getUnknownXMLObjects().push_back(hdrblock);
    }
    
    if (relayState) {
        // Create ecp:RelayState header.
        static const XMLCh RelayState[] = UNICODE_LITERAL_10(R,e,l,a,y,S,t,a,t,e);
        hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(SAML20ECP_NS, RelayState, SAML20ECP_PREFIX));
        hdrblock->setAttribute(qMU, XML_ONE);
        hdrblock->setAttribute(qActor, m_actor.get());
        auto_ptr_XMLCh rs(relayState);
        hdrblock->setTextContent(rs.get());
        header->getUnknownXMLObjects().push_back(hdrblock);
    }
    
    try {
        DOMElement* rootElement = NULL;
        if (credential) {
            if (request->getSignature()) {
                log.debug("message already signed, skipping signature operation");
                rootElement = env->marshall();
            }
            else {
                log.debug("signing the message and marshalling the envelope");
    
                // Build a Signature.
                Signature* sig = SignatureBuilder::buildSignature();
                request->setSignature(sig);    
                if (signatureAlg)
                    sig->setSignatureAlgorithm(signatureAlg);
                if (digestAlg) {
                    opensaml::ContentReference* cr = dynamic_cast<opensaml::ContentReference*>(sig->getContentReference());
                    if (cr)
                        cr->setDigestAlgorithm(digestAlg);
                }
        
                // Sign message while marshalling.
                vector<Signature*> sigs(1,sig);
                rootElement = env->marshall((DOMDocument*)NULL,&sigs,credential);
            }
        }
        else {
            log.debug("marshalling the envelope");
            rootElement = env->marshall();
        }

        stringstream s;
        s << *rootElement;
        
        if (log.isDebugEnabled())
            log.debug("marshalled envelope:\n%s", s.str().c_str());

        log.debug("sending serialized envelope");
        long ret = genericResponse.sendResponse(s);
    
        // Cleanup by destroying XML.
        delete env;
        return ret;
    }
    catch (XMLToolingException&) {
        // A bit weird...we have to "revert" things so that the message is isolated
        // so the caller can free it.
        xmlObject->getParent()->detach();
        xmlObject->detach();
        throw;
    }
}
