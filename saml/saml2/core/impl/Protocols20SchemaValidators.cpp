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
 * Protocols20SchemaValidators.cpp
 * 
 * Schema-based validators for SAML 2.0 Protocols classes
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/core/Protocols.h"

using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2p {
        
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,Artifact);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,GetComplete);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,NewID);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,RequesterID);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,SessionIndex);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,StatusMessage);
        
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,RespondTo);

        //TODO wildcard NS ##other - spec says must be a "non-SAML defined" namespace,
        // not just other than the target namespace
        class SAML_DLLLOCAL checkWildcardNS {
        public:
            void operator()(const XMLObject* xmlObject) const {
                const XMLCh* ns=xmlObject->getElementQName().getNamespaceURI();
                if (XMLString::equals(ns,SAMLConstants::SAML20P_NS) || !ns || !*ns) {
                    throw ValidationException(
                        "Object contains an illegal extension child element ($1).",
                        params(1,xmlObject->getElementQName().toString().c_str())
                        );
                }
            }
        };

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,RequestAbstractType);
            XMLOBJECTVALIDATOR_REQUIRE(RequestAbstractType,ID);
            XMLOBJECTVALIDATOR_REQUIRE(RequestAbstractType,Version);
            XMLOBJECTVALIDATOR_REQUIRE(RequestAbstractType,IssueInstant);
            if (!XMLString::equals(SAMLConstants::SAML20_VERSION, ptr->getVersion()))
                throw ValidationException("Request has wrong SAML Version.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,SubjectQuery,RequestAbstractType);
            RequestAbstractTypeSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_REQUIRE(SubjectQuery,Subject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,StatusResponseType);
            XMLOBJECTVALIDATOR_REQUIRE(StatusResponseType,ID);
            XMLOBJECTVALIDATOR_REQUIRE(StatusResponseType,Version);
            XMLOBJECTVALIDATOR_REQUIRE(StatusResponseType,IssueInstant);
            XMLOBJECTVALIDATOR_REQUIRE(StatusResponseType,Status);
            if (!XMLString::equals(SAMLConstants::SAML20_VERSION, ptr->getVersion()))
                throw ValidationException("StatusResponse has wrong SAML Version.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Extensions);
            if (!ptr->hasChildren())
                throw ValidationException("Extensions must have at least one child element.");
            const list<XMLObject*>& anys=ptr->getXMLObjects();
            for_each(anys.begin(),anys.end(),checkWildcardNS());
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,StatusCode);
            XMLOBJECTVALIDATOR_REQUIRE(StatusCode,Value);

            //TODO test this !!!
            // If this is a top-level StatusCode (ie. parent is a Status),
            // then there are only 4 valid values per SAML Core.
            if (ptr->getParent()!=NULL && ptr->getParent()->getElementQName().hasLocalPart())
            {
                QName pq = ptr->getParent()->getElementQName();

                if ( XMLString::equals(pq.getNamespaceURI(), SAMLConstants::SAML20P_NS) &&
                        XMLString::equals(pq.getLocalPart(), Status::LOCAL_NAME))
                {
                    const XMLCh* code = ptr->getValue();

                    if (!XMLString::equals(code, StatusCode::SUCCESS) &&
                        !XMLString::equals(code, StatusCode::REQUESTER) &&
                        !XMLString::equals(code, StatusCode::RESPONDER) &&
                        !XMLString::equals(code, StatusCode::VERSION_MISMATCH) )
                    {
                        throw ValidationException("Invalid value for top-level StatusCode");
                    }
                }
            }
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Status);
            XMLOBJECTVALIDATOR_REQUIRE(Status,StatusCode);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AssertionIDRequest,RequestAbstractType);
            RequestAbstractTypeSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_NONEMPTY(AssertionIDRequest,AssertionIDRef);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,RequestedAuthnContext);
            if (ptr->getAuthnContextClassRefs().empty() && ptr->getAuthnContextDeclRefs().empty())
                throw xmltooling::ValidationException("RequestedAuthnContext must have at least one AuthnContextClassRef or AuthnContextDeclRef"); 
            if (!ptr->getAuthnContextClassRefs().empty() && !ptr->getAuthnContextDeclRefs().empty())
                throw xmltooling::ValidationException("RequestedAuthnContext may not have both AuthnContextClassRef and AuthnContextDeclRef"); 
            if (!XMLString::equals(ptr->getComparison(),RequestedAuthnContext::COMPARISON_EXACT) &&
                !XMLString::equals(ptr->getComparison(),RequestedAuthnContext::COMPARISON_MINIMUM) &&
                !XMLString::equals(ptr->getComparison(),RequestedAuthnContext::COMPARISON_MAXIMUM) &&
                !XMLString::equals(ptr->getComparison(),RequestedAuthnContext::COMPARISON_BETTER))
                throw ValidationException("RequestedAuthnContext Comparison attribute must be one of: 'exact', 'minimum', 'maximum', or 'better'.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AuthnQuery,SubjectQuery);
            SubjectQuerySchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AttributeQuery,SubjectQuery);
            SubjectQuerySchemaValidator::validate(xmlObject);
            //TODO Name/NameFormat pairs of child Attributes must be unique 
            //   - whether and how to implement efficiently?
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AuthzDecisionQuery,SubjectQuery);
            SubjectQuerySchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_REQUIRE(AuthzDecisionQuery,Resource);
            XMLOBJECTVALIDATOR_NONEMPTY(AuthzDecisionQuery,Action);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,IDPEntry);
            XMLOBJECTVALIDATOR_REQUIRE(IDPEntry,ProviderID);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,IDPList);
            XMLOBJECTVALIDATOR_NONEMPTY(IDPList,IDPEntry);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Scoping);
            pair<bool,int> pc = ptr->getProxyCount();
            if (pc.first && pc.second < 0) 
                throw xmltooling::ValidationException("ProxyCount attribute on Scoping element must be non-negative"); 
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AuthnRequest,RequestAbstractType);
            RequestAbstractTypeSchemaValidator::validate(xmlObject);
            if (ptr->getAssertionConsumerServiceIndex().first 
                    && (ptr->getAssertionConsumerServiceURL()!=NULL || ptr->getProtocolBinding()!=NULL))
                throw xmltooling::ValidationException("On AuthnRequest AssertionConsumerServiceIndex is mutually exclusive with both AssertionConsumerServiceURL and ProtocolBinding");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,Response,StatusResponseType);
            StatusResponseTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,ArtifactResolve,RequestAbstractType);
            RequestAbstractTypeSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_REQUIRE(ArtifactResolve,Artifact);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,ArtifactResponse,StatusResponseType);
            StatusResponseTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,NewEncryptedID);
            XMLOBJECTVALIDATOR_REQUIRE(NewEncryptedID,EncryptedData);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,ManageNameIDRequest,RequestAbstractType);
            RequestAbstractTypeSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_ONLYONEOF(ManageNameIDRequest,NameID,EncryptedID);
            XMLOBJECTVALIDATOR_ONLYONEOF3(ManageNameIDRequest,NewID,NewEncryptedID,Terminate);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,ManageNameIDResponse,StatusResponseType);
            StatusResponseTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,LogoutRequest,RequestAbstractType);
            RequestAbstractTypeSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_ONLYONEOF3(LogoutRequest,BaseID,NameID,EncryptedID);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,LogoutResponse,StatusResponseType);
            StatusResponseTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,NameIDMappingRequest,RequestAbstractType);
            RequestAbstractTypeSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_ONLYONEOF3(NameIDMappingRequest,BaseID,NameID,EncryptedID);
            XMLOBJECTVALIDATOR_REQUIRE(NameIDMappingRequest,NameIDPolicy);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,NameIDMappingResponse,StatusResponseType);
            StatusResponseTypeSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_ONLYONEOF(NameIDMappingResponse,NameID,EncryptedID);
        END_XMLOBJECTVALIDATOR;


    };
};

#define REGISTER_ELEMENT(cname) \
    q=QName(SAMLConstants::SAML20P_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())
    
#define REGISTER_TYPE(cname) \
    q=QName(SAMLConstants::SAML20P_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())

#define REGISTER_ELEMENT_NOVAL(cname) \
    q=QName(SAMLConstants::SAML20P_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());
    
#define REGISTER_TYPE_NOVAL(cname) \
    q=QName(SAMLConstants::SAML20P_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());

void opensaml::saml2p::registerProtocolClasses() {
    QName q;
    REGISTER_ELEMENT(Artifact);
    REGISTER_ELEMENT(ArtifactResolve);
    REGISTER_ELEMENT(ArtifactResponse);
    REGISTER_ELEMENT(AssertionIDRequest);
    REGISTER_ELEMENT(AttributeQuery);
    REGISTER_ELEMENT(AuthnQuery);
    REGISTER_ELEMENT(AuthnRequest);
    REGISTER_ELEMENT(AuthzDecisionQuery);
    REGISTER_ELEMENT(Extensions);
    REGISTER_ELEMENT(GetComplete);
    REGISTER_ELEMENT(IDPEntry);
    REGISTER_ELEMENT(IDPList);
    REGISTER_ELEMENT(LogoutRequest);
    REGISTER_ELEMENT(LogoutResponse);
    REGISTER_ELEMENT(ManageNameIDRequest);
    REGISTER_ELEMENT(ManageNameIDResponse);
    REGISTER_ELEMENT(NameIDMappingRequest);
    REGISTER_ELEMENT(NameIDMappingResponse);
    REGISTER_ELEMENT_NOVAL(NameIDPolicy);
    REGISTER_ELEMENT(NewEncryptedID);
    REGISTER_ELEMENT(NewID);
    REGISTER_ELEMENT(RequestedAuthnContext);
    REGISTER_ELEMENT(RequesterID);
    REGISTER_ELEMENT(Response);
    REGISTER_ELEMENT(Scoping);
    REGISTER_ELEMENT(SessionIndex);
    REGISTER_ELEMENT(Status);
    REGISTER_ELEMENT(StatusCode);
    REGISTER_ELEMENT_NOVAL(StatusDetail);
    REGISTER_ELEMENT(StatusMessage);
    REGISTER_ELEMENT_NOVAL(Terminate);
    REGISTER_TYPE(ArtifactResolve);
    REGISTER_TYPE(ArtifactResponse);
    REGISTER_TYPE(AssertionIDRequest);
    REGISTER_TYPE(AttributeQuery);
    REGISTER_TYPE(AuthnQuery);
    REGISTER_TYPE(AuthnRequest);
    REGISTER_TYPE(AuthzDecisionQuery);
    REGISTER_TYPE(Extensions);
    REGISTER_TYPE(IDPEntry);
    REGISTER_TYPE(IDPList);
    REGISTER_TYPE(LogoutRequest);
    REGISTER_TYPE(ManageNameIDRequest);
    REGISTER_TYPE(NameIDMappingRequest);
    REGISTER_TYPE(NameIDMappingResponse);
    REGISTER_TYPE_NOVAL(NameIDPolicy);
    REGISTER_TYPE(RequestedAuthnContext);
    REGISTER_TYPE(Response);
    REGISTER_TYPE(Scoping);
    REGISTER_TYPE(Status);
    REGISTER_TYPE(StatusCode);
    REGISTER_TYPE_NOVAL(StatusDetail);
    REGISTER_TYPE_NOVAL(Terminate);

    q=QName(SAMLConstants::SAML20P_THIRDPARTY_EXT_NS,RespondTo::LOCAL_NAME);
    XMLObjectBuilder::registerBuilder(q,new RespondToBuilder());
    SchemaValidators.registerValidator(q,new RespondToSchemaValidator());
}
