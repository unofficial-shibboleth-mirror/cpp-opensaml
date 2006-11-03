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
 * SAML2POSTDecoder.cpp
 * 
 * SAML 2.0 HTTP POST binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/HTTPRequest.h"
#include "saml2/binding/SAML2POSTDecoder.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <log4cpp/Category.hh>
#include <xercesc/util/Base64.hpp>
#include <xmltooling/util/NDC.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        MessageDecoder* SAML_DLLLOCAL SAML2POSTDecoderFactory(const DOMElement* const & e)
        {
            return new SAML2POSTDecoder(e);
        }
    };
};

SAML2POSTDecoder::SAML2POSTDecoder(const DOMElement* e) {}

SAML2POSTDecoder::~SAML2POSTDecoder() {}

saml2::RootObject* SAML2POSTDecoder::decode(
    std::string& relayState,
    const GenericRequest& genericRequest,
    SecurityPolicy& policy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2POST");

    log.debug("validating input");
    const HTTPRequest* httpRequest=dynamic_cast<const HTTPRequest*>(&genericRequest);
    if (!httpRequest) {
        log.error("unable to cast request to HTTPRequest type");
        return NULL;
    }
    if (strcmp(httpRequest->getMethod(),"POST"))
        return NULL;
    const char* msg = httpRequest->getParameter("SAMLResponse");
    if (!msg)
        msg = httpRequest->getParameter("SAMLRequest");
    if (!msg)
        return NULL;
    const char* state = httpRequest->getParameter("RelayState");
    if (state)
        relayState = state;
    else
        relayState.erase();

    // Decode the base64 into SAML.
    unsigned int x;
    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(msg),&x);
    if (!decoded)
        throw BindingException("Unable to decode base64 in POST binding message.");
    log.debug("decoded SAML message:\n%s", decoded);
    istringstream is(reinterpret_cast<char*>(decoded));
    XMLString::release(&decoded);
    
    // Parse and bind the document into an XMLObject.
    DOMDocument* doc = (m_validate ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(is); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    saml2::RootObject* root = dynamic_cast<saml2::RootObject*>(xmlObject.get());
    if (!root)
        throw BindingException("XML content for SAML 2.0 HTTP-POST Decoder must be a SAML 2.0 protocol message.");
    
    try {
        if (!m_validate)
            SchemaValidators.validate(xmlObject.get());
        
        // Run through the policy.
        policy.evaluate(genericRequest, *root);
    }
    catch (XMLToolingException& ex) {
        // This is just to maximize the likelihood of attaching a source to the message for support purposes.
        if (policy.getIssuerMetadata())
            annotateException(&ex,policy.getIssuerMetadata()); // throws it

        const Issuer* claimedIssuer = root->getIssuer();
        if (!claimedIssuer) {
            // Check for assertions.
            const Response* assbag = dynamic_cast<Response*>(root);
            if (assbag) {
                const vector<Assertion*>& assertions=assbag->getAssertions();
                if (!assertions.empty())
                    claimedIssuer = assertions.front()->getIssuer();
            }
        }
    
        if (!claimedIssuer || !claimedIssuer->getName())
            throw;
        const EntityDescriptor* provider=NULL;
        if (!policy.getMetadataProvider() ||
                !(provider=policy.getMetadataProvider()->getEntityDescriptor(claimedIssuer->getName(), false))) {
            // Just record it.
            auto_ptr_char iname(claimedIssuer->getName());
            if (iname.get())
                ex.addProperty("entityID", iname.get());
            throw;
        }

        if (policy.getRole()) {
            const RoleDescriptor* roledesc=provider->getRoleDescriptor(*(policy.getRole()), samlconstants::SAML20P_NS);
            if (roledesc) annotateException(&ex,roledesc); // throws it
        }
        annotateException(&ex,provider);  // throws it
    }

    xmlObject.release();
    return root;
}
