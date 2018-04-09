/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * SimpleSigningRule.cpp
 * 
 * Blob-oriented signature checking SecurityPolicyRule.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicy.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/core/Assertions.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataCredentialCriteria.h"
#include "saml2/metadata/MetadataProvider.h"

#include <xercesc/util/Base64.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/security/SignatureTrustEngine.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/ParserPool.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

using xmlsignature::KeyInfo;
using xmlsignature::SignatureException;
using boost::scoped_ptr;

namespace opensaml {
    class SAML_DLLLOCAL SimpleSigningRule : public SecurityPolicyRule
    {
    public:
        SimpleSigningRule(const DOMElement* e);
        virtual ~SimpleSigningRule() {}
        
        const char* getType() const {
            return SIMPLESIGNING_POLICY_RULE;
        }
        bool evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;

    private:
        // Appends a raw parameter=value pair to the string.
        static bool appendParameter(string& s, const char* data, const char* name);

        bool m_errorFatal;
    };

    SecurityPolicyRule* SAML_DLLLOCAL SimpleSigningRuleFactory(const DOMElement* const & e)
    {
        return new SimpleSigningRule(e);
    }

    static const XMLCh errorFatal[] = UNICODE_LITERAL_10(e,r,r,o,r,F,a,t,a,l);
};

bool SimpleSigningRule::appendParameter(string& s, const char* data, const char* name)
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

SimpleSigningRule::SimpleSigningRule(const DOMElement* e) : m_errorFatal(XMLHelper::getAttrBool(e, false, errorFatal))
{
}

bool SimpleSigningRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    Category& log=Category::getInstance(SAML_LOGCAT ".SecurityPolicyRule.SimpleSigning");
    
    if (!policy.getIssuerMetadata()) {
        log.debug("ignoring message, no issuer metadata supplied");
        return false;
    }

    const SignatureTrustEngine* sigtrust;
    if (!(sigtrust=dynamic_cast<const SignatureTrustEngine*>(policy.getTrustEngine()))) {
        log.debug("ignoring message, no SignatureTrustEngine supplied");
        return false;
    }

    const HTTPRequest* httpRequest = dynamic_cast<const HTTPRequest*>(request);
    if (!request || !httpRequest)
        return false;

    const char* signature = request->getParameter("Signature");
    if (!signature)
        return false;
    
    const char* sigAlgorithm = request->getParameter("SigAlg");
    if (!sigAlgorithm) {
        log.error("SigAlg parameter not found, no way to verify the signature");
        return false;
    }

    string input;
    const char* pch;
    if (!strcmp(httpRequest->getMethod(), "GET")) {
        // We have to construct a string containing the signature input by accessing the
        // request directly. We can't use the decoded parameters because we need the raw
        // data and URL-encoding isn't canonical.

        // NOTE: SimpleSign for GET means Redirect binding, which means we verify over the
        // base64-encoded message directly.

        pch = httpRequest->getQueryString();
        if (!appendParameter(input, pch, "SAMLRequest="))
            appendParameter(input, pch, "SAMLResponse=");
        appendParameter(input, pch, "RelayState=");
        appendParameter(input, pch, "SigAlg=");
    }
    else {
        // With POST, the input string is concatenated from the decoded form controls.
        // GET should be this way too, but I messed up the spec, sorry.

        // NOTE: SimpleSign for POST means POST binding, which means we verify over the
        // base64-decoded XML. This sucks, because we have to decode the base64 directly.
        // Serializing the XMLObject doesn't guarantee the signature will verify (this is
        // why XMLSignature exists, and why this isn't really "simpler").

        XMLSize_t x;
        pch = httpRequest->getParameter("SAMLRequest");
        if (pch) {
            XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(pch),&x);
            if (!decoded) {
                log.warn("unable to decode base64 in POST binding message");
                return false;
            }
            input = string("SAMLRequest=") + reinterpret_cast<const char*>(decoded);
            XMLString::release((char**)&decoded);
        }
        else {
            pch = httpRequest->getParameter("SAMLResponse");
            XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(pch),&x);
            if (!decoded) {
                log.warn("unable to decode base64 in POST binding message");
                return false;
            }
            input = string("SAMLResponse=") + reinterpret_cast<const char*>(decoded);
            XMLString::release((char**)&decoded);
        }

        pch = httpRequest->getParameter("RelayState");
        if (pch)
            input = input + "&RelayState=" + pch;
        input = input + "&SigAlg=" + sigAlgorithm;
    }

    // Check for KeyInfo, but defensively (we might be able to run without it).
    KeyInfo* keyInfo=nullptr;
    pch = request->getParameter("KeyInfo");
    if (pch) {
        XMLSize_t x;
        XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(pch),&x);
        if (decoded) {
            try {
                istringstream kstrm((char*)decoded);
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
            XMLString::release((char**)&decoded);
        }
        else {
            log.warn("Failed to load KeyInfo from message: Unable to decode base64-encoded KeyInfo.");
        }
    }
    
    scoped_ptr<KeyInfo> kjanitor(keyInfo);
    auto_ptr_XMLCh alg(sigAlgorithm);

    // Set up criteria object.
    MetadataCredentialCriteria cc(*(policy.getIssuerMetadata()));
    cc.setXMLAlgorithm(alg.get());

    if (!sigtrust->validate(alg.get(), signature, keyInfo, input.c_str(), input.length(), *(policy.getMetadataProvider()), &cc)) {
        log.error("unable to verify message signature with supplied trust engine");
        if (m_errorFatal)
            throw SecurityPolicyException("Message was signed, but signature could not be verified.");
        return false;
    }

    log.debug("signature verified against message issuer");
    policy.setAuthenticated(true);
    return true;
}
