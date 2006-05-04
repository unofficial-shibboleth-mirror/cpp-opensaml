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
 * @file Assertions.h
 * 
 * XMLObjects representing the SAML 1.x Assertions schema
 */

#ifndef __saml_assertions_h__
#define __saml_assertions_h__

#include <saml/exceptions.h>
#include <saml/util/XMLConstants.h>
#include <xmltooling/ElementProxy.h>
#include <xmltooling/SimpleElement.h>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/validation/ValidatingXMLObject.h>

#define DECL_SAML1OBJECTBUILDER(cname) \
    DECL_XMLOBJECTBUILDER(SAML_API,cname,opensaml::XMLConstants::SAML1_NS,opensaml::XMLConstants::SAML1_PREFIX)

namespace opensaml {

    /**
     * @namespace saml1
     * SAML 1.x class namespace
     */
    namespace saml1 {
        DECL_XMLOBJECT_SIMPLE(SAML_API,AssertionIDReference,Reference,SAML 1.x AssertionIDReference element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,Audience,Uri,SAML 1.x Audience element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,ConfirmationMethod,Method,SAML 1.x ConfirmationMethod element);
        
        DECL_SAML1OBJECTBUILDER(AssertionIDReference);
        DECL_SAML1OBJECTBUILDER(Audience);
        DECL_SAML1OBJECTBUILDER(ConfirmationMethod);
        
#ifdef SAML_DECLARE_VALIDATORS
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AssertionIDReference);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,Audience);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,ConfirmationMethod);
#endif
    };
};

#endif /* __saml_assertions_h__ */
