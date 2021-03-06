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
 * @file saml/saml1/core/Protocols.h
 *
 * XMLObjects representing the SAML 1.x Protocols schema.
 */

#ifndef __saml1_protocols_h__
#define __saml1_protocols_h__

#include <saml/RootObject.h>
#include <saml/util/SAMLConstants.h>

#include <xmltooling/ConcreteXMLObjectBuilder.h>
#include <xmltooling/ElementExtensibleXMLObject.h>

#include <xercesc/util/XMLDateTime.hpp>

#define DECL_SAML1POBJECTBUILDER(cname) \
    DECL_XMLOBJECTBUILDER(SAML_API,cname,samlconstants::SAML1P_NS,samlconstants::SAML1P_PREFIX)

namespace xmlsignature {
    class XMLTOOL_API KeyInfo;
    class XMLTOOL_API Signature;
};

namespace opensaml {

    namespace saml1 {
        class SAML_API Action;
        class SAML_API Assertion;
        class SAML_API AssertionIDReference;
        class SAML_API AttributeDesignator;
        class SAML_API Evidence;
        class SAML_API Subject;
    };

    /**
     * @namespace opensaml::saml1p
     * SAML 1.x protocol namespace
     */
    namespace saml1p {

        DECL_XMLOBJECT_SIMPLE(SAML_API,AssertionArtifact,Artifact,SAML 1.x AssertionArtifact element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,StatusMessage,Message,SAML 1.x StatusMessage element);

        BEGIN_XMLOBJECT(SAML_API,RespondWith,xmltooling::XMLObject,SAML 1.x RespondWith element);
            /** Gets the QName content of the element. */
            virtual xmltooling::QName* getQName() const=0;
            /** Sets the QName content of the element. */
            virtual void setQName(const xmltooling::QName* qname)=0;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Query,xmltooling::XMLObject,SAML 1.x Query element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SubjectQuery,Query,SAML 1.x SubjectQuery element);
            DECL_TYPED_FOREIGN_CHILD(Subject,saml1);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthenticationQuery,SubjectQuery,SAML 1.x AuthenticationQuery element);
            DECL_STRING_ATTRIB(AuthenticationMethod,AUTHENTICATIONMETHOD);
            /** AuthenticationQueryType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AttributeQuery,SubjectQuery,SAML 1.x AttributeQuery element);
            DECL_STRING_ATTRIB(Resource,RESOURCE);
            DECL_TYPED_FOREIGN_CHILDREN(AttributeDesignator,saml1);
            /** AttributeQueryType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthorizationDecisionQuery,SubjectQuery,SAML 1.x AuthorizationDecisionQuery element);
            DECL_STRING_ATTRIB(Resource,RESOURCE);
            DECL_TYPED_FOREIGN_CHILDREN(Action,saml1);
            DECL_TYPED_FOREIGN_CHILD(Evidence,saml1);
            /** AuthorizationDecisionQueryType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,RequestAbstractType,RootObject,SAML 1.x RequestAbstractType base type);
            DECL_INTEGER_ATTRIB(MinorVersion,MINORVERSION);
            DECL_STRING_ATTRIB(RequestID,REQUESTID);
            DECL_INHERITED_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT);
            DECL_TYPED_CHILDREN(RespondWith);
            /** RequestAbstractType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Request,RequestAbstractType,SAML 1.x Request element);
            DECL_TYPED_CHILD(Query);
            DECL_TYPED_CHILD(SubjectQuery);
            DECL_TYPED_CHILD(AuthenticationQuery);
            DECL_TYPED_CHILD(AttributeQuery);
            DECL_TYPED_CHILD(AuthorizationDecisionQuery);
            DECL_TYPED_FOREIGN_CHILDREN(AssertionIDReference,saml1);
            DECL_TYPED_CHILDREN(AssertionArtifact);
            /** RequestType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,StatusCode,xmltooling::XMLObject,SAML 1.x StatusCode element);
            DECL_XMLOBJECT_ATTRIB(Value,VALUE,xmltooling::QName);
            DECL_TYPED_CHILD(StatusCode);
            /** StatusCodeType local name */
            static const XMLCh TYPE_NAME[];
            /** Success Status Code */
            static xmltooling::QName SUCCESS;
            /** Requester Error Status Code */
            static xmltooling::QName REQUESTER;
            /** Responder Error Status Code */
            static xmltooling::QName RESPONDER;
            /** Version Mismatch Error Status Code */
            static xmltooling::QName VERSIONMISMATCH;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,StatusDetail,xmltooling::ElementExtensibleXMLObject,SAML 1.x StatusDetail element);
            /** StatusDetailType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Status,opensaml::Status,SAML 1.x Status element);
            DECL_TYPED_CHILD(StatusCode);
            DECL_TYPED_CHILD(StatusMessage);
            DECL_TYPED_CHILD(StatusDetail);
            /** StatusType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ResponseAbstractType,RootObject,SAML 1.x ResponseAbstractType base type);
            DECL_INTEGER_ATTRIB(MinorVersion,MINORVERSION);
            DECL_STRING_ATTRIB(ResponseID,RESPONSEID);
            DECL_STRING_ATTRIB(InResponseTo,INRESPONSETO);
            DECL_INHERITED_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT);
            DECL_STRING_ATTRIB(Recipient,RECIPIENT);
            /** ResponseAbstractType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Response,ResponseAbstractType,SAML 1.x Response element);
            DECL_TYPED_CHILD(Status);
            DECL_TYPED_FOREIGN_CHILDREN(Assertion,saml1);
            /** ResponseType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        DECL_SAML1POBJECTBUILDER(AssertionArtifact);
        DECL_SAML1POBJECTBUILDER(AttributeQuery);
        DECL_SAML1POBJECTBUILDER(AuthenticationQuery);
        DECL_SAML1POBJECTBUILDER(AuthorizationDecisionQuery);
        DECL_SAML1POBJECTBUILDER(Request);
        DECL_SAML1POBJECTBUILDER(RespondWith);
        DECL_SAML1POBJECTBUILDER(Response);
        DECL_SAML1POBJECTBUILDER(Status);
        DECL_SAML1POBJECTBUILDER(StatusCode);
        DECL_SAML1POBJECTBUILDER(StatusDetail);
        DECL_SAML1POBJECTBUILDER(StatusMessage);

        /**
         * Builder for Query extension objects.
         *
         * This is customized to force the schema type to be specified.
         */
        class SAML_API QueryBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~QueryBuilder() {}
            /** Builder that allows element/type override. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual Query* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static Query* buildQuery(const xmltooling::QName& schemaType) {
                const QueryBuilder* b = dynamic_cast<const QueryBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML1P_NS,Query::LOCAL_NAME))
                    );
                if (b) {
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject(samlconstants::SAML1P_NS, Query::LOCAL_NAME, samlconstants::SAML1P_PREFIX, &schemaType);
#else
                    return dynamic_cast<Query*>(b->buildObject(samlconstants::SAML1P_NS, Query::LOCAL_NAME, samlconstants::SAML1P_PREFIX, &schemaType));
#endif
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for Query.");
            }
        };

        /**
         * Registers builders and validators for SAML 1.x Protocol classes into the runtime.
         */
        void SAML_API registerProtocolClasses();
    };
};

#endif /* __saml1_protocols_h__ */
