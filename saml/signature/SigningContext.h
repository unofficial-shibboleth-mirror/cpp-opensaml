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
 * @file SigningContext.h
 * 
 * SAML-specific signature construction 
 */

#ifndef __saml_signctx_h__
#define __saml_signctx_h__

#include <saml/base.h>
#include <xmltooling/signature/SigningContext.h>

namespace opensaml {

    /**
     * SAML-specific signature profile context.
     * This is not a synchronized implementation.
     */
    class SAML_API SigningContext : public virtual xmlsignature::SigningContext
    {
    public:
        /**
         * Constructor.
         * 
         * @param id            identifier of object being signed
         * @param credentials   resolver to signing key/certs to use
         * @param keyInfo       a complete KeyInfo object to attach, will be freed by context
         */
        SigningContext(const XMLCh* id, xmltooling::CredentialResolver& creds, xmlsignature::KeyInfo* keyInfo=NULL)
            : m_id(id), m_creds(creds), m_keyInfo(keyInfo) {
        }
    
        virtual ~SigningContext() {
            delete m_keyInfo;
        }

        /**
         * Given a "blank" native signature, creates signature content
         * appropriate for the SAML assertion or message being signed.
         * 
         * @param sig   native signature interface
         * @return      indicator whether ds:KeyInfo was created by context 
         */
        virtual bool createSignature(DSIGSignature* sig);

        /**
         * Gets a reference to the credential resolver supplied during construction.
         * 
         * @return  the resolver
         */
        virtual xmltooling::CredentialResolver& getCredentialResolver() {
            return m_creds;
        }
        
        /**
         * Gets a KeyInfo structure to embed.
         * Ownership of the object MUST be transferred to the caller.
         * This method will only be called if no certificates are returned from
         * the getX509Certificates() method.
         * 
         * @return  pointer to a KeyInfo structure, will be freed by caller
         */
        virtual xmlsignature::KeyInfo* getKeyInfo() {
            xmlsignature::KeyInfo* ret=m_keyInfo;
            m_keyInfo=NULL;
            return ret;
        }
        
        void addInclusivePrefix(const char* prefix) {
            m_prefixes.push_back(prefix);
        }

    protected:
        /** Identifier of object to sign. */
        const XMLCh* m_id;

        /** Reference to credentials to sign with. */
        xmltooling::CredentialResolver& m_creds;

        /** Optional pointer to KeyInfo to embed. */
        mutable xmlsignature::KeyInfo* m_keyInfo;
        
        /** Inclusive prefixes. */
        std::vector<std::string> m_prefixes;
    };

};

#endif /* __saml_signctx_h__ */
