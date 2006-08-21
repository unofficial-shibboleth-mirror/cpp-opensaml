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
 * @file saml/security/X509TrustEngine.h
 * 
 * Extended TrustEngine interface that adds validation of X.509 credentials.
 */

#ifndef __saml_x509trust_h__
#define __saml_x509trust_h__

#include <saml/security/TrustEngine.h>

namespace opensaml {

    /**
     * Extended TrustEngine interface that adds validation of X.509 credentials.
     */
    class SAML_API X509TrustEngine : public TrustEngine {
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
        X509TrustEngine(const DOMElement* e=NULL) : TrustEngine(e) {}
        
    public:
        virtual ~X509TrustEngine() {}
        
        /**
         * Determines whether an X.509 credential is valid with respect
         * to the information known about the peer.
         * 
         * A custom KeyResolver can be supplied from outside the TrustEngine.
         * Alternatively, one may be specified to the plugin constructor.
         * A non-caching, inline resolver will be used as a fallback.
         * 
         * @param certEE        end-entity certificate to validate
         * @param certChain     the complete set of certificates presented for validation (includes certEE)
         * @param role          metadata role supplying key information
         * @param checkName     true iff certificate subject/name checking has <b>NOT</b> already occurred
         * @param keyResolver   optional externally supplied KeyResolver, or NULL
         */
        virtual bool validate(
            XSECCryptoX509* certEE,
            const std::vector<XSECCryptoX509*>& certChain,
            saml2md::RoleDescriptor& role,
            bool checkName=true,
            const xmlsignature::KeyResolver* keyResolver=NULL
            )=0;
    };
    
};

#endif /* __saml_x509trust_h__ */
