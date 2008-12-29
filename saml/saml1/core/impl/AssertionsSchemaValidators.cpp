/*
*  Copyright 2001-2007 Internet2
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
 * AssertionsSchemaValidators.cpp
 *
 * Schema-based validators for SAML 1.x Assertions classes
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/core/Assertions.h"

#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmltooling;
using namespace std;
using samlconstants::SAML1_NS;

namespace opensaml {
    namespace saml1 {

        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,Action);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AssertionIDReference);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,Audience);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,ConfirmationMethod);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,NameIdentifier);

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AudienceRestrictionCondition);
            XMLOBJECTVALIDATOR_NONEMPTY(AudienceRestrictionCondition,Audience);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Conditions);
            if (!ptr->hasChildren()) {
                XMLOBJECTVALIDATOR_ONEOF(Conditions,NotBefore,NotOnOrAfter);
            }
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,SubjectConfirmation);
            XMLOBJECTVALIDATOR_NONEMPTY(SubjectConfirmation,ConfirmationMethod);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Subject);
            XMLOBJECTVALIDATOR_ONEOF(Subject,NameIdentifier,SubjectConfirmation);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,SubjectLocality);
            XMLOBJECTVALIDATOR_ONEOF(SubjectLocality,IPAddress,DNSAddress);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AuthorityBinding);
            XMLOBJECTVALIDATOR_REQUIRE(AuthorityBinding,AuthorityKind);
            XMLOBJECTVALIDATOR_REQUIRE(AuthorityBinding,Location);
            XMLOBJECTVALIDATOR_REQUIRE(AuthorityBinding,Binding);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AuthenticationStatement);
            XMLOBJECTVALIDATOR_REQUIRE(AuthenticationStatement,AuthenticationMethod);
            XMLOBJECTVALIDATOR_REQUIRE(AuthenticationStatement,AuthenticationInstant);
            XMLOBJECTVALIDATOR_REQUIRE(AuthenticationStatement,Subject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Evidence);
            if (!ptr->hasChildren())
                throw ValidationException("Evidence must have at least one child element.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AuthorizationDecisionStatement);
            XMLOBJECTVALIDATOR_REQUIRE(AuthorizationDecisionStatement,Resource);
            XMLOBJECTVALIDATOR_REQUIRE(AuthorizationDecisionStatement,Decision);
            if (!XMLString::equals(ptr->getDecision(),AuthorizationDecisionStatement::DECISION_PERMIT) &&
                !XMLString::equals(ptr->getDecision(),AuthorizationDecisionStatement::DECISION_DENY) &&
                !XMLString::equals(ptr->getDecision(),AuthorizationDecisionStatement::DECISION_INDETERMINATE))
                throw ValidationException("Decision must be one of Deny, Permit, or Indeterminate.");
            XMLOBJECTVALIDATOR_REQUIRE(AuthorizationDecisionStatement,Subject);
            XMLOBJECTVALIDATOR_NONEMPTY(AuthorizationDecisionStatement,Action);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AttributeDesignator);
            XMLOBJECTVALIDATOR_REQUIRE(AttributeDesignator,AttributeName);
            XMLOBJECTVALIDATOR_REQUIRE(AttributeDesignator,AttributeNamespace);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Attribute);
            XMLOBJECTVALIDATOR_REQUIRE(Attribute,AttributeName);
            XMLOBJECTVALIDATOR_REQUIRE(Attribute,AttributeNamespace);
            XMLOBJECTVALIDATOR_NONEMPTY(Attribute,AttributeValue);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AttributeStatement);
            XMLOBJECTVALIDATOR_NONEMPTY(AttributeStatement,Attribute);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Assertion);
            XMLOBJECTVALIDATOR_REQUIRE(Assertion,AssertionID);
            XMLOBJECTVALIDATOR_REQUIRE(Assertion,Issuer);
            XMLOBJECTVALIDATOR_REQUIRE(Assertion,IssueInstant);
            if (ptr->getAuthenticationStatements().empty() &&
                ptr->getAttributeStatements().empty() &&
                ptr->getAuthorizationDecisionStatements().empty() &&
                ptr->getSubjectStatements().empty() &&
                ptr->getStatements().empty())
                throw ValidationException("Assertion must have at least one statement.");
            pair<bool,int> minor=ptr->getMinorVersion();
            if (!minor.first)
                throw ValidationException("Assertion must have MinorVersion");
            if (minor.second==0 && ptr->getConditions() && !ptr->getConditions()->getDoNotCacheConditions().empty())
                throw ValidationException("SAML 1.0 assertions cannot contain DoNotCacheCondition elements.");
        END_XMLOBJECTVALIDATOR;

        class SAML_DLLLOCAL checkWildcardNS {
        public:
            void operator()(const XMLObject* xmlObject) const {
                const XMLCh* ns=xmlObject->getElementQName().getNamespaceURI();
                if (XMLString::equals(ns,SAML1_NS) || !ns || !*ns) {
                    throw ValidationException(
                        "Object contains an illegal extension child element ($1).",
                        params(1,xmlObject->getElementQName().toString().c_str())
                        );
                }
            }
        };

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Advice);
            const vector<XMLObject*>& anys=ptr->getUnknownXMLObjects();
            for_each(anys.begin(),anys.end(),checkWildcardNS());
        END_XMLOBJECTVALIDATOR;

    };
};

#define REGISTER_ELEMENT(cname) \
    q=xmltooling::QName(SAML1_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())

#define REGISTER_TYPE(cname) \
    q=xmltooling::QName(SAML1_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())

#define REGISTER_ELEMENT_NOVAL(cname) \
    q=xmltooling::QName(SAML1_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());

#define REGISTER_TYPE_NOVAL(cname) \
    q=xmltooling::QName(SAML1_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());

void opensaml::saml1::registerAssertionClasses() {
    xmltooling::QName q;
    REGISTER_ELEMENT(Action);
    REGISTER_ELEMENT(Advice);
    REGISTER_ELEMENT(Assertion);
    REGISTER_ELEMENT(AssertionIDReference);
    REGISTER_ELEMENT(Attribute);
    REGISTER_ELEMENT(AttributeDesignator);
    REGISTER_ELEMENT(AttributeStatement);
    REGISTER_ELEMENT_NOVAL(AttributeValue);
    REGISTER_ELEMENT(Audience);
    REGISTER_ELEMENT(AudienceRestrictionCondition);
    REGISTER_ELEMENT(AuthenticationStatement);
    REGISTER_ELEMENT(AuthorityBinding);
    REGISTER_ELEMENT(AuthorizationDecisionStatement);
    REGISTER_ELEMENT_NOVAL(Condition);
    REGISTER_ELEMENT(Conditions);
    REGISTER_ELEMENT(ConfirmationMethod);
    REGISTER_ELEMENT_NOVAL(DoNotCacheCondition);
    REGISTER_ELEMENT(Evidence);
    REGISTER_ELEMENT(NameIdentifier);
    REGISTER_ELEMENT_NOVAL(Statement);
    REGISTER_ELEMENT(Subject);
    REGISTER_ELEMENT(SubjectConfirmation);
    REGISTER_ELEMENT_NOVAL(SubjectConfirmationData);
    REGISTER_ELEMENT(SubjectLocality);
    REGISTER_TYPE(Action);
    REGISTER_TYPE(Advice);
    REGISTER_TYPE(Assertion);
    REGISTER_TYPE(Attribute);
    REGISTER_TYPE(AttributeDesignator);
    REGISTER_TYPE(AttributeStatement);
    REGISTER_TYPE(AudienceRestrictionCondition);
    REGISTER_TYPE(AuthenticationStatement);
    REGISTER_TYPE(AuthorityBinding);
    REGISTER_TYPE(AuthorizationDecisionStatement);
    REGISTER_TYPE(Conditions);
    REGISTER_TYPE_NOVAL(DoNotCacheCondition);
    REGISTER_TYPE(Evidence);
    REGISTER_TYPE(NameIdentifier);
    REGISTER_TYPE(Subject);
    REGISTER_TYPE(SubjectConfirmation);
    REGISTER_TYPE(SubjectLocality);
}
