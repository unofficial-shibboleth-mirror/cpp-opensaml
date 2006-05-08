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
#include <saml/util/SAMLConstants.h>
#include <xmltooling/ElementProxy.h>
#include <xmltooling/SimpleElement.h>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/validation/ValidatingXMLObject.h>

#define DECL_SAML1OBJECTBUILDER(cname) \
    DECL_XMLOBJECTBUILDER(SAML_API,cname,opensaml::SAMLConstants::SAML1_NS,opensaml::SAMLConstants::SAML1_PREFIX)

namespace opensaml {

    /**
     * @namespace saml1
     * SAML 1.x class namespace
     */
    namespace saml1 {
        
        class SAML_API Assertion;
        
        DECL_XMLOBJECT_SIMPLE(SAML_API,AssertionIDReference,Reference,SAML 1.x AssertionIDReference element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,Audience,Uri,SAML 1.x Audience element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,ConfirmationMethod,Method,SAML 1.x ConfirmationMethod element);
        
        BEGIN_XMLOBJECT(SAML_API,Condition,xmltooling::XMLObject,SAML 1.x Condition element);
        END_XMLOBJECT;
        
        BEGIN_XMLOBJECT(SAML_API,AudienceRestrictionCondition,Condition,SAML 1.x AudienceRestrictionCondition element);
            DECL_TYPED_CHILDREN(Audience);
            /** AudienceRestrictionConditionType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,DoNotCacheCondition,Condition,SAML 1.x DoNotCacheCondition element);
            /** DoNotCacheConditionType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Conditions,xmltooling::XMLObject,SAML 1.x Conditions element);
            DECL_XMLOBJECT_ATTRIB(NotBefore,NOTBEFORE,xmltooling::DateTime);
            DECL_XMLOBJECT_ATTRIB(NotOnOrAfter,NOTONORAFTER,xmltooling::DateTime);
            DECL_TYPED_CHILDREN(AudienceRestrictionCondition);
            DECL_TYPED_CHILDREN(DoNotCacheCondition);
            DECL_TYPED_CHILDREN(Condition);
            /** ConditionsType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,NameIdentifier,xmltooling::SimpleElement,SAML 1.x NameIdentifier element);
            DECL_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER);
            DECL_STRING_ATTRIB(Format,FORMAT);
            /** NameIdentifierType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SubjectConfirmationData,xmltooling::ElementProxy,SAML 1.x SubjectConfirmationData element);
        END_XMLOBJECT;
        
        BEGIN_XMLOBJECT(SAML_API,SubjectConfirmation,xmltooling::XMLObject,SAML 1.x SubjectConfirmation element);
            DECL_TYPED_CHILDREN(ConfirmationMethod);
            DECL_XMLOBJECT_CHILD(SubjectConfirmationData);
            DECL_TYPED_FOREIGN_CHILD(KeyInfo,xmlsignature);
            /** SubjectConfirmationType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Subject,xmltooling::XMLObject,SAML 1.x Subject element);
            DECL_TYPED_CHILD(NameIdentifier);
            DECL_TYPED_CHILD(SubjectConfirmation);
            /** SubjectType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Statement,xmltooling::XMLObject,SAML 1.x Statement element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SubjectStatement,Statement,SAML 1.x SubjectStatement element);
            DECL_TYPED_CHILD(Subject);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SubjectLocality,xmltooling::XMLObject,SAML 1.x SubjectLocality element);
            DECL_STRING_ATTRIB(IPAddress,IPADDRESS);
            DECL_STRING_ATTRIB(DNSAddress,DNSADDRESS);
            /** SubjectLocality local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthorityBinding,xmltooling::XMLObject,SAML 1.x AuthorityBinding element);
            DECL_XMLOBJECT_ATTRIB(AuthorityKind,AUTHORITYKIND,xmltooling::QName);
            DECL_STRING_ATTRIB(Location,LOCATION);
            DECL_STRING_ATTRIB(Binding,BINDING);
            /** AuthorityBinding local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthenticationStatement,SubjectStatement,SAML 1.x AuthenticationStatement element);
            DECL_STRING_ATTRIB(AuthenticationMethod,AUTHENTICATIONMETHOD);
            DECL_DATETIME_ATTRIB(AuthenticationInstant,AUTHENTICATIONINSTANT);
            DECL_TYPED_CHILD(SubjectLocality);
            DECL_TYPED_CHILDREN(AuthorityBinding);
            /** AuthenticationStatement local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Advice,xmltooling::XMLObject,SAML 1.x Advice element);
            DECL_TYPED_CHILDREN(AssertionIDReference);
            DECL_TYPED_CHILDREN(Assertion);
            DECL_XMLOBJECT_CHILDREN(Other);
            /** AdviceType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Assertion,xmltooling::XMLObject,SAML 1.x Assertion element);
            DECL_INTEGER_ATTRIB(MinorVersion,MINORVERSION);
            DECL_STRING_ATTRIB(AssertionID,ASSERTIONID);
            DECL_STRING_ATTRIB(Issuer,ISSUER);
            DECL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT);
            DECL_TYPED_CHILD(Conditions);
            DECL_TYPED_CHILD(Advice);
            DECL_TYPED_CHILDREN(Statement);
            DECL_TYPED_CHILDREN(SubjectStatement);
            DECL_TYPED_CHILDREN(AuthenticationStatement);
            DECL_TYPED_FOREIGN_CHILD(Signature,xmlsignature);
            /** AssertionType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        DECL_SAML1OBJECTBUILDER(Advice);
        DECL_SAML1OBJECTBUILDER(Assertion);
        DECL_SAML1OBJECTBUILDER(AssertionIDReference);
        DECL_SAML1OBJECTBUILDER(Audience);
        DECL_SAML1OBJECTBUILDER(AudienceRestrictionCondition);
        DECL_SAML1OBJECTBUILDER(AuthenticationStatement);
        DECL_SAML1OBJECTBUILDER(AuthorityBinding);
        DECL_SAML1OBJECTBUILDER(DoNotCacheCondition);
        DECL_SAML1OBJECTBUILDER(Conditions);
        DECL_SAML1OBJECTBUILDER(ConfirmationMethod);
        DECL_SAML1OBJECTBUILDER(NameIdentifier);
        DECL_SAML1OBJECTBUILDER(Subject);
        DECL_SAML1OBJECTBUILDER(SubjectConfirmation);
        DECL_SAML1OBJECTBUILDER(SubjectConfirmationData);
        DECL_SAML1OBJECTBUILDER(SubjectLocality);
        
        /**
         * Registers builders and validators for Assertion classes into the runtime.
         */
        void SAML_API registerAssertionClasses();
    };
};

#endif /* __saml_assertions_h__ */
