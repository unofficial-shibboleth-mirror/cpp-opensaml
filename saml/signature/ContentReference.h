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
 * @file saml/signature/ContentReference.h
 * 
 * SAML-specific signature reference profile 
 */

#ifndef __saml_sigref_h__
#define __saml_sigref_h__

#include <saml/base.h>
#include <xmltooling/signature/ContentReference.h>

#include <string>

namespace opensaml {

    class SAML_API SignableObject;

    /**
     * SAML-specific signature reference profile.
     */
    class SAML_API ContentReference : public virtual xmlsignature::ContentReference
    {
    public:
        /**
         * Constructor.
         * 
         * @param signableObject    reference to object being signed
         */
        ContentReference(const SignableObject& signableObject) : m_signableObject(signableObject) {
        }
    
        virtual ~ContentReference() {}

        /**
         * Given a "blank" native signature, creates signature reference
         * appropriate for the SAML object being signed.
         * 
         * @param sig   native signature interface
         */
        virtual void createReferences(DSIGSignature* sig);
        
        /**
         * Adds a namespace prefix for "inclusive" processing by the
         * Exclusive C14N Transform applied to the object.
         * An empty string will be transformed into "#default".
         * 
         * @param prefix    the prefix to add 
         */
        void addInclusivePrefix(const char* prefix) {
            m_prefixes.push_back(prefix);
        }

    protected:
        /** Reference to object to sign. */
        const SignableObject& m_signableObject;

        /** Inclusive prefixes. */
        std::vector<std::string> m_prefixes;
    };

};

#endif /* __saml_sigref_h__ */
