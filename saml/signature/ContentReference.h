/*
 *  Copyright 2001-2009 Internet2
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
 * SAML-specific signature reference profile.
 */

#ifndef __saml_sigref_h__
#define __saml_sigref_h__

#include <saml/base.h>

#include <set>
#include <string>
#ifdef HAVE_GOOD_STL
# include <xmltooling/unicode.h>
#endif
#include <xmltooling/signature/ContentReference.h>

namespace xmltooling {
    class XMLTOOL_API Namespace;
    class XMLTOOL_API XMLObject;
};

namespace opensaml {

    class SAML_API SignableObject;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

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
        ContentReference(const SignableObject& signableObject);
    
        virtual ~ContentReference();

        /**
         * Given a "blank" native signature, creates signature reference
         * appropriate for the SAML object being signed.
         * 
         * @param sig   native signature interface
         */
        virtual void createReferences(DSIGSignature* sig);
        
        /**
         * Adds a namespace prefix for "inclusive" processing by an
         * Exclusive C14N Transform applied to the object.
         * An empty string will be transformed into "#default".
         * 
         * @param prefix    the prefix to add 
         */
        void addInclusivePrefix(const XMLCh* prefix);
        
        /**
         * Sets the digest algorithm for the signature reference,
         * using a constant.
         * 
         * @param digest    the digest algorithm
         */
        void setDigestAlgorithm(const XMLCh* digest);

        /**
         * Sets the canonicalization method to include in the reference,
         * using a constant.
         * 
         * @param c14n  the canonicalization method
         */
        void setCanonicalizationMethod(const XMLCh* c14n);
        
    private:
        const SignableObject& m_signableObject;
        std::set<xmltooling::xstring> m_prefixes;
        const XMLCh* m_digest;
        const XMLCh* m_c14n;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
};

#endif /* __saml_sigref_h__ */
