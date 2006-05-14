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
     * Singleton object that manages library startup/shutdown.configuration.
     */
    class SAML_API SigningContext : public virtual xmlsignature::SigningContext
    {
    public:
        /**
         * Constructor.
         * 
         * @param id    identifier of object being signed
         * @param key   signing key to use, will be freed by context
         * @param certs a certificate chain to embed, or NULL
         */
        SigningContext(const XMLCh* id, XSECCryptoKey* key, const std::vector<XSECCryptoX509*>* certs=NULL)
            : m_id(id), m_key(key), m_certs(certs), m_keyInfo(NULL) {
        }
        
        /**
         * Constructor.
         * 
         * @param id        identifier of object being signed
         * @param key       signing key to use, will be freed by context
         * @param keyInfo   a complete KeyInfo object to attach, will be freed by context
         */
        SigningContext(const XMLCh* id, XSECCryptoKey* key, xmlsignature::KeyInfo* keyInfo)
            : m_id(id), m_key(key), m_certs(NULL), m_keyInfo(keyInfo) {
        }
    
        virtual ~SigningContext() {
            delete m_key;
            delete m_keyInfo;
        }

        /**
         * Given a "blank" native signature, asks the context to define the
         * appropriate signature transforms, references, etc.
         * This method MAY attach ds:KeyInfo information, or a set of X.509
         * certificates can be returned from the SigningContext::getX509Certificates()
         * method instead.
         * 
         * @param sig   native signature interface
         */
        virtual void createSignature(DSIGSignature* sig) const;
        
        /**
         * Gets a reference to a collection of certificates to append to
         * the ds:KeyInfo element in a ds:X509Data chain.
         * The certificate corresponding to the signing key SHOULD be
         * first, followed by any additional intermediates to append. 
         * 
         * @return  an immutable collection of certificates to embed
         */
        virtual const std::vector<XSECCryptoX509*>* getX509Certificates() const {
            return m_certs;
        }

        /**
         * Gets a KeyInfo structure to embed.
         * Ownership of the object MUST be transferred to the caller.
         * This method will only be called if no certificates are returned from
         * the getX509Certificates() method.
         * 
         * @return  pointer to a KeyInfo structure, will be freed by caller
         */
        virtual xmlsignature::KeyInfo* getKeyInfo() const {
            xmlsignature::KeyInfo* ret=m_keyInfo;
            m_keyInfo=NULL;
            return ret;
        }
        
        /**
         * Gets the signing key to use.
         * Must be compatible with the intended signature algorithm. Ownership of the key
         * MUST be transferred to the caller.
         * 
         * @return  pointer to a signing key, will be freed by caller
         */
        virtual XSECCryptoKey* getSigningKey() const {
            XSECCryptoKey* ret=m_key;
            m_key=NULL;
            return ret;
        }
        
        void addInclusivePrefix(const char* prefix) {
            m_prefixes.push_back(prefix);
        }

    protected:
        /** Identifier of object to sign. */
        const XMLCh* m_id;

        /** Signing key. */
        mutable XSECCryptoKey* m_key;
        
        /** Optional pointer to certificate chain to embed. */
        const std::vector<XSECCryptoX509*>* m_certs;

        /** Optional pointer to KeyInfo to embed. */
        mutable xmlsignature::KeyInfo* m_keyInfo;
        
        /** Inclusive prefixes. */
        std::vector<std::string> m_prefixes;
    };

};

#endif /* __saml_signctx_h__ */
