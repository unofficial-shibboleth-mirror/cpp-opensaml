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
 * @file VerifyingContext.h
 * 
 * SAML-specific signature verification 
 */

#ifndef __saml_verctx_h__
#define __saml_verctx_h__

#include <saml/base.h>
#include <xmltooling/signature/VerifyingContext.h>

namespace opensaml {

    /**
     * Singleton object that manages library startup/shutdown.configuration.
     */
    class SAML_API VerifyingContext : public virtual xmlsignature::VerifyingContext
    {
    public:
        /**
         * Constructor.
         * 
         * @param id    identifier of object being verified
         */
        VerifyingContext(const XMLCh* id) : m_id(id) {}
        
        virtual ~VerifyingContext() {}

        /**
         * Given a native signature, asks the context to verify the signature
         * in accordance with the relying party's requirements.
         * 
         * @param sig   native signature object
         * 
         * @throws SignatureException   raised if signature is invalid
         */
        virtual void verifySignature(DSIGSignature* sig) const;
        
    protected:
        /** Identifier of object to verify. */
        const XMLCh* m_id;
    };

};

#endif /* __saml_verctx_h__ */
