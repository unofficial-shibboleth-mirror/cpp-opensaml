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
 * @file Protocols.h
 * 
 * XMLObjects representing the SAML 2.0 Protocols schema
 */

#ifndef __saml2_protocols_h__
#define __saml2_protocols_h__

#include <saml/saml2/core/Assertions.h>


#define DECL_SAML2POBJECTBUILDER(cname) \
    DECL_XMLOBJECTBUILDER(SAML_API,cname,opensaml::SAMLConstants::SAML20P_NS,opensaml::SAMLConstants::SAML20P_PREFIX)

namespace opensaml {

    /**
     * @namespace saml2p
     * SAML 2.0 protocol namespace
     */
    namespace saml2p {

        //TODO sync C++ and Java class/interface names, e.g. -Type or no -Type, etc

        DECL_XMLOBJECT_SIMPLE(SAML_API,Artifact,Artifact,SAML 2.0 Artifact element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,GetComplete,GetComplete,SAML 2.0 GetComplete element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,NewID,NewID,SAML 2.0 NewID element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,RequesterID,RequesterID,SAML 2.0 RequesterID element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,SessionIndex,SessionIndex,SAML 2.0 SessionIndex element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,StatusMessage,Message,SAML 2.0 StatusMessage element);

        BEGIN_XMLOBJECT(SAML_API,Extensions,xmltooling::ElementProxy,SAML 2.0 protocol Extensions element);
            /** ExtensionsType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Request,SignableObject,SAML 2.0 Request element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(Version,VER);
            DECL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT);
            DECL_STRING_ATTRIB(Destination,DESTINATION);
            DECL_STRING_ATTRIB(Consent,CONSENT);
            DECL_TYPED_FOREIGN_CHILD(Issuer,saml2);
            DECL_TYPED_FOREIGN_CHILD(Signature,xmlsignature);
            DECL_TYPED_CHILD(Extensions);
            /** RequestAbstractType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,StatusCode,xmltooling::XMLObject,SAML 2.0 StatusCode element);
            DECL_STRING_ATTRIB(Value,VALUE);
            DECL_TYPED_CHILD(StatusCode);
            /** StatusCodeType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,StatusDetail,xmltooling::XMLObject,SAML 2.0 StatusDetail element);
            DECL_XMLOBJECT_CHILDREN(Detail);
            /** StatusDetailType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Status,xmltooling::XMLObject,SAML 2.0 Status element);
            DECL_TYPED_CHILD(StatusCode);
            DECL_TYPED_CHILD(StatusMessage);
            DECL_TYPED_CHILD(StatusDetail);
            /** StatusType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,StatusResponse,SignableObject,SAML 2.0 StatusResponse element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(InResponseTo,INRESPONSETO);
            DECL_STRING_ATTRIB(Version,VER);
            DECL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT);
            DECL_STRING_ATTRIB(Destination,DESTINATION);
            DECL_STRING_ATTRIB(Consent,CONSENT);

            DECL_TYPED_FOREIGN_CHILD(Issuer,saml2);
            DECL_TYPED_FOREIGN_CHILD(Signature,xmlsignature);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILD(Status);

            /** StatusResponseType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AssertionIDRequest,Request,SAML 2.0 AssertionIDRequest element);
            DECL_TYPED_FOREIGN_CHILDREN(AssertionIDRef,saml2);
            /** AssertionIDRequest local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SubjectQuery,Request,SAML 2.0 SubjectQuery element);
            DECL_TYPED_FOREIGN_CHILD(Subject,saml2);
            /** SubjectQueryType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,RequestedAuthnContext,xmltooling::XMLObject,SAML 2.0 RequestedAuthnContext element);
            //TODO whether, and how, to enforce the controlled vocabulary (schema enumeration) for the Comparison attrib, as in the Java ? 
            DECL_STRING_ATTRIB(Comparison,COMPARISON);
            DECL_TYPED_FOREIGN_CHILDREN(AuthnContextClassRef,saml2);
            DECL_TYPED_FOREIGN_CHILDREN(AuthnContextDeclRef,saml2);
            /** exact Comparison */
            static const XMLCh COMPARISON_EXACT[];
            /** minimum Comparison */
            static const XMLCh COMPARISON_MINIMUM[];
            /** maximum Comparison */
            static const XMLCh COMPARISON_MAXIMUM[];
            /** better Comparison */
            static const XMLCh COMPARISON_BETTER[];
            /** RequestedAuthnContextType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnQuery,SubjectQuery,SAML 2.0 AuthnQuery element);
            DECL_STRING_ATTRIB(SessionIndex,SESSIONINDEX);
            DECL_TYPED_CHILD(RequestedAuthnContext);
            /** AuthnQueryType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AttributeQuery,SubjectQuery,SAML 2.0 AttributeQuery element);
            DECL_TYPED_FOREIGN_CHILDREN(Attribute,saml2);
            /** AttributeQueryType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;
        
        BEGIN_XMLOBJECT(SAML_API,AuthzDecisionQuery,SubjectQuery,SAML 2.0 AuthzDecisionQuery element);
            DECL_STRING_ATTRIB(Resource,RESOURCE);
            DECL_TYPED_FOREIGN_CHILDREN(Action,saml2);
            DECL_TYPED_FOREIGN_CHILD(Evidence,saml2);
            /** AuthzDecisionQueryType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,NameIDPolicy,xmltooling::XMLObject,SAML 2.0 NameIDPolicy element);
            DECL_STRING_ATTRIB(Format,FORMAT);
            DECL_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER);
            DECL_BOOLEAN_ATTRIB(AllowCreate,ALLOWCREATE);
            /** NameIDPolicyType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,IDPEntry,xmltooling::XMLObject,SAML2.0 IDPEntry element);
            DECL_STRING_ATTRIB(ProviderID,PROVIDERID);
            DECL_STRING_ATTRIB(Name,NAME);
            DECL_STRING_ATTRIB(Loc,LOC);
            /** IDPEntryType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,IDPList,xmltooling::XMLObject,SAML 2.0 IDPList element);
            DECL_TYPED_CHILDREN(IDPEntry);
            DECL_TYPED_CHILD(GetComplete);
            /** IDPListType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Scoping,xmltooling::XMLObject,SAML 2.0 Scoping element);
            DECL_INTEGER_ATTRIB(ProxyCount,PROXYCOUNT);
            DECL_TYPED_CHILD(IDPList);
            DECL_TYPED_CHILDREN(RequesterID);
            /** ScopingType local name */
            static const XMLCh TYPE_NAME[];
            /** ProxyCount value to express no restriction*/
            static const int NO_PROXY_COUNT;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnRequest,Request,SAML 2.0 AuthnRequest element);
            DECL_BOOLEAN_ATTRIB(ForceAuthn,FORCEAUTHN);
            DECL_BOOLEAN_ATTRIB(IsPassive,ISPASSIVE);
            DECL_STRING_ATTRIB(ProtocolBinding,PROTOCOLBINDING);
            DECL_INTEGER_ATTRIB(AssertionConsumerServiceIndex,ASSERTIONCONSUMERSERVICEINDEX);
            DECL_STRING_ATTRIB(AssertionConsumerServiceURL,ASSERTIONCONSUMERSERVICEURL);
            DECL_INTEGER_ATTRIB(AttributeConsumingServiceIndex,ATTRIBUTECONSUMINGSERVICEINDEX);
            DECL_STRING_ATTRIB(ProviderName,PROVIDERNAME);

            DECL_TYPED_FOREIGN_CHILD(Subject,saml2);
            DECL_TYPED_CHILD(NameIDPolicy);
            DECL_TYPED_FOREIGN_CHILD(Conditions,saml2);
            DECL_TYPED_CHILD(RequestedAuthnContext);
            DECL_TYPED_CHILD(Scoping);
            /** AuthnRequestType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Response,StatusResponse,SAML 2.0 Response element);
            DECL_TYPED_FOREIGN_CHILDREN(Assertion,saml2);
            DECL_TYPED_FOREIGN_CHILDREN(EncryptedAssertion,saml2);
            /** ResponseType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ArtifactResolve,Request,SAML 2.0 ArtifactResolve element);
            DECL_TYPED_CHILD(Artifact);
            /** ArtifiactResolveType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ArtifactResponse,StatusResponse,SAML 2.0 ArtifactResponse element);
            DECL_XMLOBJECT_CHILD(Payload);
            /** ArtifiactResponseType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Terminate,xmltooling::XMLObject,SAML 2.0 Terminate element);
            /** TerminateType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,NewEncryptedID,saml2::EncryptedElementType,SAML 2.0 NewEncryptedID element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ManageNameIDRequest,Request,SAML 2.0 ManageNameIDRequest element);
            DECL_TYPED_FOREIGN_CHILD(NameID,saml2);
            DECL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            DECL_TYPED_CHILD(NewID);
            DECL_TYPED_CHILD(NewEncryptedID);
            DECL_TYPED_CHILD(Terminate);
            /** ManageNameIDRequestType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ManageNameIDResponse,StatusResponse,SAML 2.0 ManageNameIDResponse element);
        END_XMLOBJECT;
        
        BEGIN_XMLOBJECT(SAML_API,LogoutRequest,Request,SAML 2.0 LogoutRequest element);
            DECL_STRING_ATTRIB(Reason,REASON);
            DECL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER);
            DECL_TYPED_FOREIGN_CHILD(BaseID,saml2);
            DECL_TYPED_FOREIGN_CHILD(NameID,saml2);
            DECL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            DECL_TYPED_CHILDREN(SessionIndex);
            /** LogoutRequestType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,LogoutResponse,StatusResponse,SAML 2.0 LogoutResponse element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,NameIDMappingRequest,Request,SAML 2.0 NameIDMappingRequest element);
            DECL_TYPED_FOREIGN_CHILD(BaseID,saml2);
            DECL_TYPED_FOREIGN_CHILD(NameID,saml2);
            DECL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            DECL_TYPED_CHILD(NameIDPolicy);
            /** NameIDMappingRequestType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,NameIDMappingResponse,StatusResponse,SAML 2.0 NameIDMappingResponse element);
            DECL_TYPED_FOREIGN_CHILD(NameID,saml2);
            DECL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            /** NameIDMappingResponseType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        // Builders
        DECL_SAML2POBJECTBUILDER(Artifact);
        DECL_SAML2POBJECTBUILDER(ArtifactResolve);
        DECL_SAML2POBJECTBUILDER(ArtifactResponse);
        DECL_SAML2POBJECTBUILDER(AssertionIDRequest);
        DECL_SAML2POBJECTBUILDER(AttributeQuery);
        DECL_SAML2POBJECTBUILDER(AuthnQuery);
        DECL_SAML2POBJECTBUILDER(AuthnRequest);
        DECL_SAML2POBJECTBUILDER(AuthzDecisionQuery);
        DECL_SAML2POBJECTBUILDER(Extensions);
        DECL_SAML2POBJECTBUILDER(GetComplete);
        DECL_SAML2POBJECTBUILDER(IDPEntry);
        DECL_SAML2POBJECTBUILDER(IDPList);
        DECL_SAML2POBJECTBUILDER(LogoutRequest);
        DECL_SAML2POBJECTBUILDER(LogoutResponse);
        DECL_SAML2POBJECTBUILDER(ManageNameIDRequest);
        DECL_SAML2POBJECTBUILDER(ManageNameIDResponse);
        DECL_SAML2POBJECTBUILDER(NameIDMappingRequest);
        DECL_SAML2POBJECTBUILDER(NameIDMappingResponse);
        DECL_SAML2POBJECTBUILDER(NameIDPolicy);
        DECL_SAML2POBJECTBUILDER(NewEncryptedID);
        DECL_SAML2POBJECTBUILDER(NewID);
        DECL_SAML2POBJECTBUILDER(RequestedAuthnContext);
        DECL_SAML2POBJECTBUILDER(RequesterID);
        DECL_SAML2POBJECTBUILDER(Response);
        DECL_SAML2POBJECTBUILDER(Scoping);
        DECL_SAML2POBJECTBUILDER(SessionIndex);
        DECL_SAML2POBJECTBUILDER(Status);
        DECL_SAML2POBJECTBUILDER(StatusCode);
        DECL_SAML2POBJECTBUILDER(StatusDetail);
        DECL_SAML2POBJECTBUILDER(StatusMessage);
        DECL_SAML2POBJECTBUILDER(Terminate);

        //
        // Custom builders
        //

        /**
         * Builder for StatusResponse objects.
         * 
         * This is customized to force the element name to be specified.
         */
        class SAML_API StatusResponseBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~StatusResponseBuilder() {}
            /** Builder that allows element/type override. */
            virtual StatusResponse* buildObject(
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL
                ) const;
        
            /** Singleton builder. */
            static StatusResponse* buildStatusResponse(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL) {
                const StatusResponseBuilder* b = dynamic_cast<const StatusResponseBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(SAMLConstants::SAML20P_NS,StatusResponse::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(SAMLConstants::SAML20P_NS,StatusResponse::TYPE_NAME,SAMLConstants::SAML20P_PREFIX);
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for StatusResponse.");
            }
        };

        
        /**
         * Registers builders and validators for SAML 2.0 Protocol classes into the runtime.
         */
        void SAML_API registerProtocolClasses();

        /**
         * Validator suite for SAML 2.0 Protocol schema validation.
         */
        extern SAML_API xmltooling::ValidatorSuite ProtocolSchemaValidators;
    };
};

#endif /* __saml2_protocols_h__ */
