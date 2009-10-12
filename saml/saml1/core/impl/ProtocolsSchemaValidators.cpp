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
 * ProtocolsSchemaValidators.cpp
 *
 * Schema-based validators for SAML 1.x Protocols classes
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/core/Protocols.h"

#include <xmltooling/validation/Validator.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml1p;
using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmltooling;
using namespace std;
using samlconstants::SAML1P_NS;

namespace opensaml {
    namespace saml1p {

        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AssertionArtifact);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,StatusMessage);

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,RespondWith);
            XMLOBJECTVALIDATOR_REQUIRE(RespondWith,QName);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AuthenticationQuery);
            XMLOBJECTVALIDATOR_REQUIRE(AuthenticationQuery,AuthenticationMethod);
            XMLOBJECTVALIDATOR_REQUIRE(AuthenticationQuery,Subject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AttributeQuery);
            XMLOBJECTVALIDATOR_REQUIRE(AttributeQuery,Subject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AuthorizationDecisionQuery);
            XMLOBJECTVALIDATOR_REQUIRE(AuthorizationDecisionQuery,Subject);
            XMLOBJECTVALIDATOR_REQUIRE(AuthorizationDecisionQuery,Resource);
            XMLOBJECTVALIDATOR_NONEMPTY(AuthorizationDecisionQuery,Action);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Request);
            XMLOBJECTVALIDATOR_REQUIRE(Request,RequestID);
            XMLOBJECTVALIDATOR_REQUIRE(Request,IssueInstant);
            pair<bool,int> minor=ptr->getMinorVersion();
            if (!minor.first)
                throw ValidationException("Request must have MinorVersion");
            int count=0;
            if (ptr->getQuery()!=NULL)
                count++;
            if (!ptr->getAssertionIDReferences().empty())
                count++;
            if (!ptr->getAssertionArtifacts().empty())
                count++;
            if (count != 1)
                throw ValidationException("Request must have either a query, >0 assertion references, or >0 artifacts.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,StatusCode);
            XMLOBJECTVALIDATOR_REQUIRE(StatusCode,Value);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Status);
            XMLOBJECTVALIDATOR_REQUIRE(Status,StatusCode);
            const xmltooling::QName* value=ptr->getStatusCode()->getValue();
            if (!value || (*value!=StatusCode::SUCCESS && *value!=StatusCode::REQUESTER &&
                *value!=StatusCode::RESPONDER && *value!=StatusCode::VERSIONMISMATCH))
                throw ValidationException("Top-level status code not one of the allowable values.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Response);
            XMLOBJECTVALIDATOR_REQUIRE(Response,ResponseID);
            XMLOBJECTVALIDATOR_REQUIRE(Response,IssueInstant);
            XMLOBJECTVALIDATOR_REQUIRE(Response,Status);
            pair<bool,int> minor=ptr->getMinorVersion();
            if (!minor.first)
                throw ValidationException("Response must have MinorVersion");
        END_XMLOBJECTVALIDATOR;
    };
};

#define REGISTER_ELEMENT(cname) \
    q=xmltooling::QName(SAML1P_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())

#define REGISTER_TYPE(cname) \
    q=xmltooling::QName(SAML1P_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())

#define REGISTER_ELEMENT_NOVAL(cname) \
    q=xmltooling::QName(SAML1P_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());

#define REGISTER_TYPE_NOVAL(cname) \
    q=xmltooling::QName(SAML1P_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());

void opensaml::saml1p::registerProtocolClasses() {
    xmltooling::QName q;
    REGISTER_ELEMENT(AssertionArtifact);
    REGISTER_ELEMENT(AttributeQuery);
    REGISTER_ELEMENT(AuthenticationQuery);
    REGISTER_ELEMENT(AuthorizationDecisionQuery);
    REGISTER_ELEMENT_NOVAL(Query);
    REGISTER_ELEMENT(Request);
    REGISTER_ELEMENT(RespondWith);
    REGISTER_ELEMENT(Response);
    REGISTER_ELEMENT(Status);
    REGISTER_ELEMENT(StatusCode);
    REGISTER_ELEMENT_NOVAL(StatusDetail);
    REGISTER_ELEMENT(StatusMessage);
    REGISTER_TYPE(AttributeQuery);
    REGISTER_TYPE(AuthenticationQuery);
    REGISTER_TYPE(AuthorizationDecisionQuery);
    REGISTER_TYPE(Request);
    REGISTER_TYPE(Response);
    REGISTER_TYPE(Status);
    REGISTER_TYPE(StatusCode);
    REGISTER_TYPE_NOVAL(StatusDetail);
}
