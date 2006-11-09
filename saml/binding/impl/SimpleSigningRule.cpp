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
 * SimpleSigningRule.cpp
 * 
 * Blob-oriented signature checking SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "RootObject.h"
#include "binding/HTTPRequest.h"
#include "binding/SimpleSigningRule.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "security/TrustEngine.h"

#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoProvider.hpp>
#include <xsec/framework/XSECException.hpp>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

using xmlsignature::KeyInfo;

namespace opensaml {
    SecurityPolicyRule* SAML_DLLLOCAL SimpleSigningRuleFactory(const DOMElement* const & e)
    {
        return new SimpleSigningRule(e);
    }

    // Appends a raw parameter=value pair to the string.
    static bool appendParameter(string& s, const char* data, const char* name)
    {
        const char* start = strstr(data,name);
        if (!start)
            return false;
        if (!s.empty())
            s += '&';
        const char* end = strchr(start,'&');
        if (end)
            s.append(start, end-start);
        else
            s.append(start);
        return true;
    }
};


pair<saml2::Issuer*,const saml2md::RoleDescriptor*> SimpleSigningRule::evaluate(
    const GenericRequest& request,
    const XMLObject& message,
    const MetadataProvider* metadataProvider,
    const QName* role,
    const opensaml::TrustEngine* trustEngine,
    const MessageExtractor& extractor
    ) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.SimpleSigning");
    log.debug("evaluating simple signing policy");
    
    pair<saml2::Issuer*,const RoleDescriptor*> ret = pair<saml2::Issuer*,const RoleDescriptor*>(NULL,NULL);  
    
    if (!metadataProvider || !role || !trustEngine) {
        log.debug("ignoring message, no metadata supplied");
        return ret;
    }
    
    const char* signature = request.getParameter("Signature");
    if (!signature) {
        log.debug("ignoring unsigned message");
        return ret;
    }
    
    const char* sigAlgorithm = request.getParameter("SigAlg");
    if (!sigAlgorithm) {
        log.error("SigAlg parameter not found, no way to verify the signature");
        return ret;
    }

    try {
        log.debug("extracting issuer from message");
        pair<saml2::Issuer*,const XMLCh*> issuerInfo = extractor.getIssuerAndProtocol(message);
        
        auto_ptr<saml2::Issuer> issuer(issuerInfo.first);
        if (!issuerInfo.first || !issuerInfo.second ||
                (issuer->getFormat() && !XMLString::equals(issuer->getFormat(), saml2::NameIDType::ENTITY))) {
            log.warn("issuer identity not estabished, or was not an entityID");
            return ret;
        }
        
        log.debug("searching metadata for message issuer...");
        const EntityDescriptor* entity = metadataProvider->getEntityDescriptor(issuer->getName());
        if (!entity) {
            auto_ptr_char temp(issuer->getName());
            log.warn("no metadata found, can't establish identity of issuer (%s)", temp.get());
            return ret;
        }

        log.debug("matched assertion issuer against metadata, searching for applicable role...");
        const RoleDescriptor* roledesc=entity->getRoleDescriptor(*role, issuerInfo.second);
        if (!roledesc) {
            log.warn("unable to find compatible role (%s) in metadata", role->toString().c_str());
            return ret;
        }

        string input;
        const char* pch;
        const HTTPRequest& httpRequest = dynamic_cast<const HTTPRequest&>(request);
        if (!strcmp(httpRequest.getMethod(), "GET")) {
            // We have to construct a string containing the signature input by accessing the
            // request directly. We can't use the decoded parameters because we need the raw
            // data and URL-encoding isn't canonical.
            pch = httpRequest.getQueryString();
            if (!appendParameter(input, pch, "SAMLRequest="))
                appendParameter(input, pch, "SAMLResponse=");
            appendParameter(input, pch, "RelayState=");
            appendParameter(input, pch, "SigAlg=");
        }
        else {
            // With POST, the input string is concatenated from the decoded form controls.
            // GET should be this way too, but I messed up the spec, sorry.
            pch = httpRequest.getParameter("SAMLRequest");
            if (pch)
                input = string("SAMLRequest=") + pch;
            else {
                pch = httpRequest.getParameter("SAMLResponse");
                input = string("SAMLResponse=") + pch;
            }
            pch = httpRequest.getParameter("RelayState");
            if (pch)
                input = input + "&RelayState=" + pch;
            input = input + "&SigAlg=" + sigAlgorithm;
        }

        // Check for KeyInfo, but defensively (we might be able to run without it).
        KeyInfo* keyInfo=NULL;
        pch = request.getParameter("KeyInfo");
        if (pch) {
            try {
                istringstream kstrm(pch);
                DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(kstrm);
                XercesJanitor<DOMDocument> janitor(doc);
                XMLObject* kxml = XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true);
                janitor.release();
                if (!(keyInfo=dynamic_cast<KeyInfo*>(kxml)))
                    delete kxml;
            }
            catch (XMLToolingException& ex) {
                log.warn("Failed to load KeyInfo from message: %s", ex.what());
            }
        }
        
        auto_ptr<KeyInfo> kjanitor(keyInfo);
        auto_ptr_XMLCh alg(sigAlgorithm);
        
        if (!trustEngine->validate(alg.get(), signature, keyInfo, input.c_str(), input.length(), *roledesc, metadataProvider->getKeyResolver())) {
            log.error("unable to verify signature on message with supplied trust engine");
            return ret;
        }

        if (log.isDebugEnabled()) {
            auto_ptr_char iname(entity->getEntityID());
            log.debug("message from (%s), signature verified", iname.get());
        }
        
        ret.first = issuer.release();
        ret.second = roledesc;
    }
    catch (bad_cast&) {
        // Just trap it.
        log.warn("caught a bad_cast while extracting issuer");
    }
    return ret;
}
