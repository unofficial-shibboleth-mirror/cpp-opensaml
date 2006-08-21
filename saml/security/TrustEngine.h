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
 * @file saml/security/TrustEngine.h
 * 
 * SAML-specific TrustEngine API
 */

#ifndef __saml_trust_h__
#define __saml_trust_h__

#include <saml/base.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/signature/KeyResolver.h>

namespace opensaml {

    /**
     * Adapts SAML metadata as a source of KeyInfo for a TrustEngine
     * and adds SAML-specific signature validation.
     */
    class SAML_API TrustEngine {
        MAKE_NONCOPYABLE(TrustEngine);
    protected:
        /**
         * Constructor.
         * 
         * If a DOM is supplied, the following XML content is supported:
         * 
         * <ul>
         *  <li>&lt;KeyResolver&gt; elements with a type attribute
         * </ul>
         * 
         * XML namespaces are ignored in the processing of this content.
         * 
         * @param e DOM to supply configuration for provider
         */
        TrustEngine(const DOMElement* e=NULL) {}
        
    public:
        virtual ~TrustEngine() {}

        /**
         * Determines whether a signed SAML object is correct and valid with respect
         * to the information known about the issuer.
         * 
         * A custom KeyResolver can be supplied from outside the TrustEngine.
         * Alternatively, one may be specified to the plugin constructor.
         * A non-caching, inline resolver will be used as a fallback.
         * 
         * @param sig           reference to a signature object to validate
         * @param role          metadata role supplying key information
         * @param keyResolver   optional externally supplied KeyResolver, or NULL
         */
        virtual bool validate(
            xmlsignature::Signature& sig,
            saml2md::RoleDescriptor& role,
            const xmlsignature::KeyResolver* keyResolver=NULL
            )=0;
    };
    

    /**
     * Registers TrustEngine classes into the runtime.
     */
    void SAML_API registerTrustEngines();

    /** TrustEngine based on explicit key information resolved from metadata. */
    #define EXPLICIT_KEY_SAMLTRUSTENGINE  "org.opensaml.security.ExplicitKeyTrustEngine"
};

#endif /* __saml_trust_h__ */
