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
 * MetadataSchemaValidators.cpp
 * 
 * Schema-based validators for SAML 2.0 Metadata classes
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/metadata/Metadata.h"

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {
        
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,ActionNamespace);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AffiliateMember);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,AttributeProfile);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,Company);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,EmailAddress);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,GivenName);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,NameIDFormat);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,SourceID);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,SurName);
        XMLOBJECTVALIDATOR_SIMPLE(SAML_DLLLOCAL,TelephoneNumber);

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,localizedNameType);
            XMLOBJECTVALIDATOR_REQUIRE(localizedNameType,TextContent);
            XMLOBJECTVALIDATOR_REQUIRE(localizedNameType,Lang);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,localizedURIType);
            XMLOBJECTVALIDATOR_REQUIRE(localizedNameType,TextContent);
            XMLOBJECTVALIDATOR_REQUIRE(localizedURIType,Lang);
        END_XMLOBJECTVALIDATOR;
        
        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,OrganizationName,localizedNameType);
            localizedNameTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,OrganizationDisplayName,localizedNameType);
            localizedNameTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,OrganizationURL,localizedURIType);
            localizedURITypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        class SAML_DLLLOCAL checkWildcardNS {
        public:
            void operator()(const XMLObject* xmlObject) const {
                const XMLCh* ns=xmlObject->getElementQName().getNamespaceURI();
                if (XMLString::equals(ns,SAMLConstants::SAML20MD_NS) || !ns || !*ns) {
                    throw ValidationException(
                        "Object contains an illegal extension child element ($1).",
                        params(1,xmlObject->getElementQName().toString().c_str())
                        );
                }
            }
        };

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Extensions);
            if (!ptr->hasChildren())
                throw ValidationException("Extensions must have at least one child element.");
            const list<XMLObject*>& anys=ptr->getXMLObjects();
            for_each(anys.begin(),anys.end(),checkWildcardNS());
        END_XMLOBJECTVALIDATOR;
        
        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,Organization);
            XMLOBJECTVALIDATOR_NONEMPTY(Organization,OrganizationName);
            XMLOBJECTVALIDATOR_NONEMPTY(Organization,OrganizationDisplayName);
            XMLOBJECTVALIDATOR_NONEMPTY(Organization,OrganizationURL);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,ContactPerson);
            if (!ptr->hasChildren())
                throw ValidationException("ContactPerson must have at least one child element.");
            if (!XMLString::equals(ptr->getContactType(),ContactPerson::CONTACT_TECHNICAL) &&
                !XMLString::equals(ptr->getContactType(),ContactPerson::CONTACT_SUPPORT) &&
                !XMLString::equals(ptr->getContactType(),ContactPerson::CONTACT_ADMINISTRATIVE) &&
                !XMLString::equals(ptr->getContactType(),ContactPerson::CONTACT_BILLING) &&
                !XMLString::equals(ptr->getContactType(),ContactPerson::CONTACT_OTHER))
                throw ValidationException("ContactPerson contactType must be one of the defined values.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AdditionalMetadataLocation);
            XMLOBJECTVALIDATOR_REQUIRE(AdditionalMetadataLocation,Namespace);
            XMLOBJECTVALIDATOR_REQUIRE(AdditionalMetadataLocation,Location);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,KeyDescriptor);
            XMLOBJECTVALIDATOR_REQUIRE(KeyDescriptor,KeyInfo);
            if (ptr->getUse() &&
                !XMLString::equals(ptr->getUse(),KeyDescriptor::KEYTYPE_ENCRYPTION) &&
                !XMLString::equals(ptr->getUse(),KeyDescriptor::KEYTYPE_SIGNING))
                throw ValidationException("KeyDescriptor use must be empty or one of the defined values.");
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,RoleDescriptor);
            XMLOBJECTVALIDATOR_REQUIRE(RoleDescriptor,ProtocolSupportEnumeration);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,EndpointType);
            XMLOBJECTVALIDATOR_REQUIRE(EndpointType,Binding);
            XMLOBJECTVALIDATOR_REQUIRE(EndpointType,Location);
            const list<XMLObject*>& anys=ptr->getXMLObjects();
            for_each(anys.begin(),anys.end(),checkWildcardNS());
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,IndexedEndpointType,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_REQUIRE_INTEGER(IndexedEndpointType,Index);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,ArtifactResolutionService,IndexedEndpointType);
            IndexedEndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,SingleLogoutService,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,ManageNameIDService,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,SingleSignOnService,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,NameIDMappingService,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AssertionIDRequestService,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,IDPSSODescriptor,RoleDescriptor);
            RoleDescriptorSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_NONEMPTY(IDPSSODescriptor,SingleSignOnService);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,ServiceName,localizedNameType);
            localizedNameTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,ServiceDescription,localizedNameType);
            localizedNameTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,RequestedAttribute);
            XMLOBJECTVALIDATOR_REQUIRE(RequestedAttribute,Name);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AttributeConsumingService);
            XMLOBJECTVALIDATOR_REQUIRE_INTEGER(AttributeConsumingService,Index);
            XMLOBJECTVALIDATOR_NONEMPTY(AttributeConsumingService,ServiceName);
            XMLOBJECTVALIDATOR_NONEMPTY(AttributeConsumingService,RequestedAttribute);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AssertionConsumerService,IndexedEndpointType);
            IndexedEndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,SPSSODescriptor,RoleDescriptor);
            RoleDescriptorSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_NONEMPTY(SPSSODescriptor,AssertionConsumerService);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AuthnQueryService,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AuthnAuthorityDescriptor,RoleDescriptor);
            RoleDescriptorSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_NONEMPTY(AuthnAuthorityDescriptor,AuthnQueryService);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AuthzService,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,PDPDescriptor,RoleDescriptor);
            RoleDescriptorSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_NONEMPTY(PDPDescriptor,AuthzService);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AttributeService,EndpointType);
            EndpointTypeSchemaValidator::validate(xmlObject);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR_SUB(SAML_DLLLOCAL,AttributeAuthorityDescriptor,RoleDescriptor);
            RoleDescriptorSchemaValidator::validate(xmlObject);
            XMLOBJECTVALIDATOR_NONEMPTY(AttributeAuthorityDescriptor,AttributeService);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,AffiliationDescriptor);
            XMLOBJECTVALIDATOR_REQUIRE(AffiliationDescriptor,AffiliationOwnerID);
            XMLOBJECTVALIDATOR_NONEMPTY(AffiliationDescriptor,AffiliateMember);
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,EntityDescriptor);
            XMLOBJECTVALIDATOR_REQUIRE(EntityDescriptor,EntityID);
            if (ptr->getRoleDescriptors().empty() &&
                ptr->getIDPSSODescriptors().empty() &&
                ptr->getSPSSODescriptors().empty() &&
                ptr->getAuthnAuthorityDescriptors().empty() &&
                ptr->getAttributeAuthorityDescriptors().empty() &&
                ptr->getPDPDescriptors().empty()) {
                    
                if (!ptr->getAffiliationDescriptor())
                    throw ValidationException("EntityDescriptor must have at least one child role or affiliation descriptor.");
            }
            else if (ptr->getAffiliationDescriptor()) {
                throw ValidationException("EntityDescriptor cannot have both an AffiliationDescriptor and role descriptors.");
            }
        END_XMLOBJECTVALIDATOR;

        BEGIN_XMLOBJECTVALIDATOR(SAML_DLLLOCAL,EntitiesDescriptor);
            if (ptr->getEntityDescriptors().empty() && ptr->getEntitiesDescriptors().empty())
                throw ValidationException("EntitiesDescriptor must contain at least one child descriptor."); 
        END_XMLOBJECTVALIDATOR;
    };
};

#define REGISTER_ELEMENT(cname) \
    q=QName(SAMLConstants::SAML20MD_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    MetadataSchemaValidators.registerValidator(q,new cname##SchemaValidator())
    
#define REGISTER_TYPE(cname) \
    q=QName(SAMLConstants::SAML20MD_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    MetadataSchemaValidators.registerValidator(q,new cname##SchemaValidator())

#define REGISTER_ELEMENT_NOVAL(cname) \
    q=QName(SAMLConstants::SAML20MD_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());
    
#define REGISTER_TYPE_NOVAL(cname) \
    q=QName(SAMLConstants::SAML20MD_NS,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder());

ValidatorSuite opensaml::saml2md::MetadataSchemaValidators("MetadataSchemaValidators");

void opensaml::saml2md::registerMetadataClasses() {
    QName q;
    REGISTER_ELEMENT(AdditionalMetadataLocation);
    REGISTER_ELEMENT(AffiliateMember);
    REGISTER_ELEMENT(AffiliationDescriptor);
    REGISTER_ELEMENT(ArtifactResolutionService);
    REGISTER_ELEMENT(AssertionConsumerService);
    REGISTER_ELEMENT(AssertionIDRequestService);
    REGISTER_ELEMENT(AttributeAuthorityDescriptor);;
    REGISTER_ELEMENT(AttributeConsumingService);
    REGISTER_ELEMENT(AttributeProfile);
    REGISTER_ELEMENT(AttributeService);
    REGISTER_ELEMENT(AuthnAuthorityDescriptor);
    REGISTER_ELEMENT(AuthnQueryService);
    REGISTER_ELEMENT(AuthzService);
    REGISTER_ELEMENT(Company);
    REGISTER_ELEMENT(ContactPerson);
    REGISTER_ELEMENT(EmailAddress);
    REGISTER_ELEMENT(EntitiesDescriptor);
    REGISTER_ELEMENT(EntityDescriptor);
    REGISTER_ELEMENT(Extensions);
    REGISTER_ELEMENT(GivenName);
    REGISTER_ELEMENT(IDPSSODescriptor);
    REGISTER_ELEMENT(KeyDescriptor);
    REGISTER_ELEMENT(ManageNameIDService);
    REGISTER_ELEMENT(NameIDFormat);
    REGISTER_ELEMENT(NameIDMappingService);
    REGISTER_ELEMENT(Organization);
    REGISTER_ELEMENT(OrganizationDisplayName);
    REGISTER_ELEMENT(OrganizationName);
    REGISTER_ELEMENT(OrganizationURL);
    REGISTER_ELEMENT(PDPDescriptor);
    REGISTER_ELEMENT(RequestedAttribute);
    REGISTER_ELEMENT(ServiceDescription);
    REGISTER_ELEMENT(ServiceName);
    REGISTER_ELEMENT(SingleLogoutService);
    REGISTER_ELEMENT(SingleSignOnService);
    REGISTER_ELEMENT(SPSSODescriptor);
    REGISTER_ELEMENT(SurName);
    REGISTER_ELEMENT(TelephoneNumber);
    REGISTER_TYPE(AdditionalMetadataLocation);
    REGISTER_TYPE(AffiliationDescriptor);
    REGISTER_TYPE(AttributeAuthorityDescriptor);;
    REGISTER_TYPE(AttributeConsumingService);
    REGISTER_TYPE(AuthnAuthorityDescriptor);
    REGISTER_TYPE(ContactPerson);
    REGISTER_TYPE(EndpointType);
    REGISTER_TYPE(EntitiesDescriptor);
    REGISTER_TYPE(EntityDescriptor);
    REGISTER_TYPE(Extensions);
    REGISTER_TYPE(IDPSSODescriptor);
    REGISTER_TYPE(IndexedEndpointType);
    REGISTER_TYPE(KeyDescriptor);
    REGISTER_TYPE(localizedNameType);
    REGISTER_TYPE(localizedURIType);
    REGISTER_TYPE(Organization);
    REGISTER_TYPE(PDPDescriptor);
    REGISTER_TYPE(RequestedAttribute);
    REGISTER_TYPE(SPSSODescriptor);

    q=QName(SAMLConstants::SAML1MD_NS,SourceID::LOCAL_NAME);
    XMLObjectBuilder::registerBuilder(q,new SourceIDBuilder());
    MetadataSchemaValidators.registerValidator(q,new SourceIDSchemaValidator());

    q=QName(SAMLConstants::SAML20MD_QUERY_EXT_NS,ActionNamespace::LOCAL_NAME);
    XMLObjectBuilder::registerBuilder(q,new ActionNamespaceBuilder());
    MetadataSchemaValidators.registerValidator(q,new ActionNamespaceSchemaValidator());

    q=QName(SAMLConstants::SAML20MD_QUERY_EXT_NS,AuthnQueryDescriptorType::TYPE_NAME);
    XMLObjectBuilder::registerBuilder(q,new AuthnQueryDescriptorTypeBuilder());
    MetadataSchemaValidators.registerValidator(q,new RoleDescriptorSchemaValidator());

    q=QName(SAMLConstants::SAML20MD_QUERY_EXT_NS,AttributeQueryDescriptorType::TYPE_NAME);
    XMLObjectBuilder::registerBuilder(q,new AttributeQueryDescriptorTypeBuilder());
    MetadataSchemaValidators.registerValidator(q,new RoleDescriptorSchemaValidator());

    q=QName(SAMLConstants::SAML20MD_QUERY_EXT_NS,AuthzDecisionQueryDescriptorType::TYPE_NAME);
    XMLObjectBuilder::registerBuilder(q,new AuthzDecisionQueryDescriptorTypeBuilder());
    MetadataSchemaValidators.registerValidator(q,new RoleDescriptorSchemaValidator());
}
