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
 * Assertions20SchemaValidators.cpp
 *
 * Schema-based validators for SAML 2.0 Assertions classes
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/core/Assertions.h"

#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace std;
using samlconstants::SAML20_NS;

namespace opensaml {
    namespace saml2 {

        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,Action);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AssertionIDRef);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AssertionURIRef);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,Audience);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AuthnContextClassRef);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AuthnContextDeclRef);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AuthenticatingAuthority);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,NameIDType);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,NameID);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,Issuer);

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,EncryptedElementType);
            XMLOBJECTVALIDATOR_REQUIRE(EncryptedElementType,EncryptedData);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,EncryptedID,EncryptedElementType);
            EncryptedElementTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,EncryptedAttribute,EncryptedElementType);
            EncryptedElementTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,EncryptedAssertion,EncryptedElementType);
            EncryptedElementTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AudienceRestriction);
            XMLOBJECTVALIDATOR_NONEMPTY(AudienceRestriction,Audience);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,ProxyRestriction);
            if (ptr->getAudiences().empty()) {
                XMLOBJECTVALIDATOR_REQUIRE_INTEGER(ProxyRestriction,Count);
            }
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Conditions);
            if (!ptr->hasChildren()) {
                XMLOBJECTVALIDATOR_ONEOF(Conditions,NotBefore,NotOnOrAfter);
            }
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,KeyInfoConfirmationDataType);
            XMLOBJECTVALIDATOR_NONEMPTY(KeyInfoConfirmationDataType,KeyInfo);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,SubjectConfirmation);
            XMLOBJECTVALIDATOR_REQUIRE(SubjectConfirmation,Method);
            int count=0;
            if (ptr->getBaseID())
                count++;
            if (ptr->getNameID())
                count++;
            if (ptr->getEncryptedID())
                count++;
            if (count > 1)
                throw ValidationException("SubjectConfirmation cannot contain multiple identifier elements.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Subject);
            int count=0;
            if (ptr->getBaseID())
                count++;
            if (ptr->getNameID())
                count++;
            if (ptr->getEncryptedID())
                count++;
            if (count > 1)
                throw ValidationException("Subject cannot contain multiple identifier elements.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,SubjectLocality);
            XMLOBJECTVALIDATOR_ONEOF(SubjectLocality,Address,DNSName);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AuthnContext);
            if (!ptr->getAuthnContextClassRef()) {
                XMLOBJECTVALIDATOR_ONLYONEOF(AuthnContext,AuthnContextDeclRef,AuthnContextDecl);
            }
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AuthnStatement);
            XMLOBJECTVALIDATOR_REQUIRE(AuthnStatement,AuthnInstant);
            XMLOBJECTVALIDATOR_REQUIRE(AuthnStatement,AuthnContext);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Evidence);
            if (!ptr->hasChildren())
                throw ValidationException("Evidence must have at least one child element.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AuthzDecisionStatement);
            XMLOBJECTVALIDATOR_REQUIRE(AuthzDecisionStatement,Resource);
            XMLOBJECTVALIDATOR_REQUIRE(AuthzDecisionStatement,Decision);
            if (!XMLString::equals(ptr->getDecision(),AuthzDecisionStatement::DECISION_PERMIT) &&
                !XMLString::equals(ptr->getDecision(),AuthzDecisionStatement::DECISION_DENY) &&
                !XMLString::equals(ptr->getDecision(),AuthzDecisionStatement::DECISION_INDETERMINATE))
                throw ValidationException("Decision must be one of Deny, Permit, or Indeterminate.");
            XMLOBJECTVALIDATOR_NONEMPTY(AuthzDecisionStatement,Action);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Attribute);
            XMLOBJECTVALIDATOR_REQUIRE(Attribute,Name);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AttributeStatement);
            XMLOBJECTVALIDATOR_NONEMPTY(AttributeStatement,Attribute);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Assertion);
            XMLOBJECTVALIDATOR_REQUIRE(Assertion,Version);
            if (!XMLString::equals(samlconstants::SAML20_VERSION, ptr->getVersion()))
                throw ValidationException("Assertion has wrong SAML Version.");
            XMLOBJECTVALIDATOR_REQUIRE(Assertion,ID);
            XMLOBJECTVALIDATOR_REQUIRE(Assertion,IssueInstant);
            XMLOBJECTVALIDATOR_REQUIRE(Assertion,Issuer);
            if ((!ptr->getAuthnStatements().empty() ||
                !ptr->getAttributeStatements().empty() ||
                !ptr->getAuthzDecisionStatements().empty()) && !ptr->getSubject())
                throw ValidationException("Assertion with standard statements must have a Subject.");
        END_XMLOBJECTVALIDATOR;

        class SAML_DLLLOCAL checkWildcardNS {
        public:
            void operator()(const XMLObject* xmlObject) const {
                const XMLCh* ns=xmlObject->getElementQName().getNamespaceURI();
                if (XMLString::equals(ns,SAML20_NS) || !ns || !*ns) {
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
    q=QName(SAML20_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())

#define REGISTER_TYPE(cname) \
    q=QName(SAML20_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())

#define REGISTER_ELEMENT_NOVAL(cname) \
    q=QName(SAML20_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());

#define REGISTER_TYPE_NOVAL(cname) \
    q=QName(SAML20_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());

void opensaml::saml2::registerAssertionClasses() {
    QName q;
    REGISTER_ELEMENT(Action);
    REGISTER_ELEMENT(Advice);
    REGISTER_ELEMENT(Assertion);
    REGISTER_ELEMENT(AssertionIDRef);
    REGISTER_ELEMENT(AssertionURIRef);
    REGISTER_ELEMENT(Attribute);
    REGISTER_ELEMENT(AttributeStatement);
    REGISTER_ELEMENT_NOVAL(AttributeValue);
    REGISTER_ELEMENT(Audience);
    REGISTER_ELEMENT(AudienceRestriction);
    REGISTER_ELEMENT(AuthenticatingAuthority);
    REGISTER_ELEMENT(AuthnContext);
    REGISTER_ELEMENT(AuthnContextClassRef);
    REGISTER_ELEMENT_NOVAL(AuthnContextDecl);
    REGISTER_ELEMENT(AuthnContextDeclRef);
    REGISTER_ELEMENT(AuthnStatement);
    REGISTER_ELEMENT(AuthzDecisionStatement);
    REGISTER_ELEMENT_NOVAL(Condition);
    REGISTER_ELEMENT(Conditions);
    REGISTER_ELEMENT(EncryptedAssertion);
    REGISTER_ELEMENT(EncryptedAttribute);
    REGISTER_ELEMENT(EncryptedID);
    REGISTER_ELEMENT(Evidence);
    REGISTER_ELEMENT(Issuer);
    REGISTER_ELEMENT(NameID);
    REGISTER_ELEMENT_NOVAL(OneTimeUse);
    REGISTER_ELEMENT(ProxyRestriction);
    REGISTER_ELEMENT_NOVAL(Statement);
    REGISTER_ELEMENT(Subject);
    REGISTER_ELEMENT(SubjectConfirmation);
    REGISTER_ELEMENT_NOVAL(SubjectConfirmationData);
    REGISTER_ELEMENT(SubjectLocality);
    REGISTER_TYPE(Action);
    REGISTER_TYPE(Advice);
    REGISTER_TYPE(Assertion);
    REGISTER_TYPE(Attribute);
    REGISTER_TYPE(AttributeStatement);
    REGISTER_TYPE(AudienceRestriction);
    REGISTER_TYPE(AuthnContext);
    REGISTER_TYPE(AuthnStatement);
    REGISTER_TYPE(AuthzDecisionStatement);
    REGISTER_TYPE(Conditions);
    REGISTER_TYPE(Evidence);
    REGISTER_TYPE(KeyInfoConfirmationDataType);
    REGISTER_TYPE(NameIDType);
    REGISTER_TYPE_NOVAL(OneTimeUse);
    REGISTER_TYPE(ProxyRestriction);
    REGISTER_TYPE(Subject);
    REGISTER_TYPE(SubjectConfirmation);
    REGISTER_TYPE(SubjectLocality);
}
