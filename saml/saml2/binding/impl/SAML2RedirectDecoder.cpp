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
 * SAML2RedirectDecoder.cpp
 * 
 * SAML 2.0 HTTP Redirect binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/binding/SAML2Redirect.h"
#include "saml2/binding/SAML2RedirectDecoder.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "security/X509TrustEngine.h"

#include <log4cpp/Category.hh>
#include <xercesc/util/Base64.hpp>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        MessageDecoder* SAML_DLLLOCAL SAML2RedirectDecoderFactory(const DOMElement* const & e)
        {
            return new SAML2RedirectDecoder(e);
        }
    };
};

SAML2RedirectDecoder::SAML2RedirectDecoder(const DOMElement* e) {}

SAML2RedirectDecoder::~SAML2RedirectDecoder() {}

XMLObject* SAML2RedirectDecoder::decode(
    string& relayState,
    const RoleDescriptor*& issuer,
    const XMLCh*& securityMech,
    const HTTPRequest& httpRequest,
    const MetadataProvider* metadataProvider,
    const QName* role,
    const opensaml::TrustEngine* trustEngine
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2Redirect");

    log.debug("validating input");
    if (strcmp(httpRequest.getMethod(),"GET"))
        return NULL;
    const char* msg = httpRequest.getParameter("SAMLResponse");
    if (!msg)
        msg = httpRequest.getParameter("SAMLRequest");
    if (!msg)
        return NULL;
    const char* state = httpRequest.getParameter("RelayState");
    if (state)
        relayState = state;
    else
        relayState.erase();
    state = httpRequest.getParameter("SAMLEncoding");
    if (state && strcmp(state,samlconstants::SAML20_BINDING_URL_ENCODING_DEFLATE)) {
        log.warn("SAMLEncoding (%s) was not recognized", state);
        return NULL;
    }

    // Decode the compressed message into SAML. First we base64-decode it.
    unsigned int x;
    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(msg),&x);
    if (!decoded)
        throw BindingException("Unable to decode base64 in Redirect binding message.");
    
    // Now we have to inflate it.
    stringstream str;
    if (inflate((char*)decoded, x, str)==0) {
        XMLString::release(&decoded);
        throw BindingException("Unable to inflate Redirect binding message.");
    }

    XMLString::release(&decoded);
    
    // Parse and bind the document into an XMLObject.
    DOMDocument* doc = (m_validate ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(str);
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    StatusResponseType* response = NULL;
    RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(xmlObject.get());
    if (!request) {
        response = dynamic_cast<StatusResponseType*>(xmlObject.get());
        if (!response)
            throw BindingException("XML content for SAML 2.0 HTTP-Redirect Decoder must be a SAML 2.0 protocol message.");
    }
    
    /* For SAML 2, the issuer can be established either from the message, or in some profiles
     * it's possible to omit it and defer to assertions in a Response.
     * The Issuer is later matched against metadata, and then trust checking can be applied.
     */
    const Issuer* claimedIssuer = request ? request->getIssuer() : response->getIssuer();
    if (!claimedIssuer) {
        // Check assertion option. I cannot resist the variable name, for the sake of google.
        const Response* assbag = dynamic_cast<const Response*>(response);
        if (assbag) {
            const vector<Assertion*>& assertions=assbag->getAssertions();
            if (!assertions.empty())
                claimedIssuer = assertions.front()->getIssuer();
        }
    }

    const EntityDescriptor* provider=NULL;
    try {
        if (!m_validate)
            SchemaValidators.validate(xmlObject.get());
        
        // Check destination URL.
        auto_ptr_char dest(request ? request->getDestination() : response->getDestination());
        const char* dest2 = httpRequest.getRequestURL();
        if (!dest.get() || !*(dest.get())) {
            log.error("signed SAML message missing Destination attribute");
            throw BindingException("Signed SAML message missing Destination attribute identifying intended destination.");
        }
        else if (dest.get() && (!dest2 || !*dest2 || strcmp(dest.get(),dest2))) {
            log.error("Redirect targeted at (%s), but delivered to (%s)", dest.get(), dest2 ? dest2 : "none");
            throw BindingException("SAML message delivered with Redirect to incorrect server URL.");
        }
        
        // Check freshness.
        time_t now = time(NULL);
        if ((request ? request->getIssueInstant()->getEpoch() : response->getIssueInstant()->getEpoch())
                < now-(2*XMLToolingConfig::getConfig().clock_skew_secs))
            throw BindingException("Detected expired Redirect binding message.");
        
        // Check replay.
        ReplayCache* replayCache = XMLToolingConfig::getConfig().getReplayCache();
        if (replayCache) {
            auto_ptr_char id(xmlObject->getXMLID());
            if (!replayCache->check("SAML2Redirect", id.get(), response->getIssueInstant()->getEpoch() + (2*XMLToolingConfig::getConfig().clock_skew_secs))) {
                log.error("replay detected of message ID (%s)", id.get());
                throw BindingException("Rejecting replayed message ID ($1).", params(1,id.get()));
            }
        }
        else
            log.warn("replay cache was not provided, this is a serious security risk!");
        
        issuer = NULL;
        securityMech = false;
        log.debug("attempting to establish issuer and integrity of message...");
        
        // If we can't identify the issuer, we're done, since we can't lookup or verify anything.
        if (!claimedIssuer || !claimedIssuer->getName()) {
            log.warn("unable to establish identity of message issuer");
            return xmlObject.release();
        }
        else if (claimedIssuer->getFormat() && !XMLString::equals(claimedIssuer->getFormat(), NameIDType::ENTITY)) {
            auto_ptr_char iformat(claimedIssuer->getFormat());
            log.warn("message issuer was in an unsupported format (%s)", iformat.get());
            return xmlObject.release();
        }
        
        log.debug("searching metadata for assertion issuer...");
        provider=metadataProvider ? metadataProvider->getEntityDescriptor(claimedIssuer->getName()) : NULL;
        if (provider) {
            log.debug("matched assertion issuer against metadata, searching for applicable role...");
            issuer=provider->getRoleDescriptor(*role, samlconstants::SAML20P_NS);
            if (issuer) {
                /*
                if (trustEngine && signature) {
                    if (!trustEngine->validate(*signature, *issuer, metadataProvider->getKeyResolver())) {
                        log.error("unable to verify signature on message with supplied trust engine");
                        throw BindingException("Message signature failed verification.");
                    }
                    else {
                        securityMech = samlconstants::SAML20P_NS;
                    }
                }
                else {
                    log.warn("unable to authenticate the message, leaving untrusted");
                }
                */
            }
            else {
                log.warn("unable to find compatible SAML 2.0 role (%s) in metadata", role->toString().c_str());
            }
            if (log.isDebugEnabled()) {
                auto_ptr_char iname(provider->getEntityID());
                log.debug("message from (%s), integrity %sverified", iname.get(), securityMech ? "" : "NOT ");
            }
        }
        else {
            auto_ptr_char temp(claimedIssuer->getName());
            log.warn("no metadata found, can't establish identity of issuer (%s)", temp.get());
        }
    }
    catch (XMLToolingException& ex) {
        if (!provider) {
            if (!claimedIssuer || !claimedIssuer->getName())
                throw;
            if (!metadataProvider || !(provider=metadataProvider->getEntityDescriptor(claimedIssuer->getName(), false))) {
                // Just record it.
                auto_ptr_char iname(claimedIssuer->getName());
                if (iname.get())
                    ex.addProperty("entityID", iname.get());
                throw;
            }
        }
        if (!issuer)
            issuer=provider->getRoleDescriptor(*role, samlconstants::SAML20P_NS);
        if (issuer) annotateException(&ex,issuer); // throws it
        annotateException(&ex,provider);  // throws it
    }

    return xmlObject.release();
}
