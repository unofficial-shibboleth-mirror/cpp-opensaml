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
 * @file saml/signature/SignableObject.h
 * 
 * Base class for SAML objects that can be signed. 
 */

#ifndef __saml_signable_h__
#define __saml_signable_h__

#include <saml/base.h>
#include <xmltooling/XMLObject.h>

namespace xmlsignature {
    class XMLTOOL_API Signature;
};

namespace opensaml {

    /**
     * Base class for SAML objects that can be signed.
     */
    class SAML_API SignableObject : public virtual xmltooling::XMLObject
    {
    public:
        virtual ~SignableObject();
        
        /**
         * Returns the enveloped Signature from the object.
         *
         * @return the enveloped Signature, or nullptr
         */
        virtual xmlsignature::Signature* getSignature() const=0;

        /**
         * Sets an enveloped Signature in the object.
         *
         * @param sig the enveloped Signature, or nullptr
         */
        virtual void setSignature(xmlsignature::Signature* sig)=0;

    protected:
        SignableObject();

        /**
         * Search the object for non-visible namespaces, and pin them
         * on the root of the object where necessary, adding them to
         * the inclusive prefix list for signing purposes.
         */
        void declareNonVisibleNamespaces() const;
    };

};

#endif /* __saml_signable_h__ */
