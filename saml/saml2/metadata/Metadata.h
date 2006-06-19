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
 * @file Metadata.h
 * 
 * XMLObjects representing the SAML 2.0 Metadata schema
 */

#ifndef __saml2_metadata_h__
#define __saml2_metadata_h__

#include <saml/saml2/core/Assertions.h>
#include <saml/util/SAMLConstants.h>

#include <xmltooling/AttributeExtensibleXMLObject.h>
#include <xmltooling/ElementProxy.h>
#include <xmltooling/SimpleElement.h>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/encryption/Encryption.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/validation/ValidatingXMLObject.h>

#define DECL_SAML2MDOBJECTBUILDER(cname) \
    DECL_XMLOBJECTBUILDER(SAML_API,cname,opensaml::SAMLConstants::SAML20MD_NS,opensaml::SAMLConstants::SAML20MD_PREFIX)

namespace opensaml {

    /**
     * @namespace saml2md
     * SAML 2.0 metadata namespace
     */
    namespace saml2md {
        
        DECL_XMLOBJECT_SIMPLE(SAML_API,AffiliateMember,ID,SAML 2.0 AffiliateMember element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,AttributeProfile,ProfileURI,SAML 2.0 AttributeProfile element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,Company,Name,SAML 2.0 Company element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,EmailAddress,Address,SAML 2.0 EmailAddress element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,GivenName,Name,SAML 2.0 GivenName element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,NameIDFormat,Format,SAML 2.0 NameIDFormat element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,SurName,Name,SAML 2.0 SurName element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,TelephoneNumber,Number,SAML 2.0 TelephoneNumber element);

        BEGIN_XMLOBJECT(SAML_API,localizedNameType,xmltooling::SimpleElement,SAML 2.0 localizedNameType type);
            DECL_STRING_ATTRIB(Lang,LANG);
            /** localizedNameType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,localizedURIType,xmltooling::SimpleElement,SAML 2.0 localizedURIType type);
            DECL_STRING_ATTRIB(Lang,LANG);
            /** localizedURIType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,OrganizationName,localizedNameType,SAML 2.0 OrganizationName element);
            DECL_XMLOBJECT_CONTENT(Name);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,OrganizationDisplayName,localizedNameType,SAML 2.0 OrganizationDisplayName element);
            DECL_XMLOBJECT_CONTENT(Name);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,OrganizationURL,localizedURIType,SAML 2.0 OrganizationURL element);
            DECL_XMLOBJECT_CONTENT(URL);
        END_XMLOBJECT;
        
        BEGIN_XMLOBJECT(SAML_API,Extensions,xmltooling::ElementProxy,SAML 2.0 Extensions element);
            /** ExtensionsType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Organization,xmltooling::AttributeExtensibleXMLObject,SAML 2.0 Organization element);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILDREN(OrganizationName);
            DECL_TYPED_CHILDREN(OrganizationDisplayName);
            DECL_TYPED_CHILDREN(OrganizationURL);
            /** OrganizationType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ContactPerson,xmltooling::AttributeExtensibleXMLObject,SAML 2.0 ContactPerson element);
            DECL_STRING_ATTRIB(ContactType,CONTACTTYPE);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILD(Company);
            DECL_TYPED_CHILD(GivenName);
            DECL_TYPED_CHILD(SurName);
            DECL_TYPED_CHILDREN(EmailAddress);
            DECL_TYPED_CHILDREN(TelephoneNumber);
            /** ContactType local name */
            static const XMLCh TYPE_NAME[];
            /** technical Contact Type */
            static const XMLCh CONTACT_TECHNICAL[];
            /** support Contact Type */
            static const XMLCh CONTACT_SUPPORT[];
            /** administrative Contact Type */
            static const XMLCh CONTACT_ADMINISTRATIVE[];
            /** billing Contact Type */
            static const XMLCh CONTACT_BILLING[];
            /** other Contact Type */
            static const XMLCh CONTACT_OTHER[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AdditionalMetadataLocation,xmltooling::SimpleElement,SAML 2.0 AdditionalMetadataLocation element);
            DECL_STRING_ATTRIB(Namespace,NAMESPACE);
            DECL_XMLOBJECT_CONTENT(Location);
            /** AdditionalMetadataLocationType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,KeyDescriptor,xmltooling::XMLObject,SAML 2.0 KeyDescriptor element);
            DECL_STRING_ATTRIB(Use,USE);
            DECL_TYPED_FOREIGN_CHILD(KeyInfo,xmlsignature);
            DECL_TYPED_FOREIGN_CHILDREN(EncryptionMethod,xmlencryption);
            /** KeyDescriptorType local name */
            static const XMLCh TYPE_NAME[];
            /** encryption Key Type */
            static const XMLCh KEYTYPE_ENCRYPTION[];
            /** signing Key Type */
            static const XMLCh KEYTYPE_SIGNING[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT2(SAML_API,RoleDescriptor,xmltooling::AttributeExtensibleXMLObject,SignableObject,SAML 2.0 RoleDescriptor abstract element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL);
            DECL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION);
            DECL_STRING_ATTRIB(ProtocolSupportEnumeration,PROTOCOLSUPPORTENUMERATION);
            DECL_STRING_ATTRIB(ErrorURL,ERRORURL);
            DECL_TYPED_FOREIGN_CHILD(Signature,xmlsignature);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILDREN(KeyDescriptor);
            DECL_TYPED_CHILD(Organization);
            DECL_TYPED_CHILDREN(ContactPerson);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT2(SAML_API,EndpointType,xmltooling::ElementProxy,xmltooling::AttributeExtensibleXMLObject,SAML 2.0 EndpointType type);
            DECL_STRING_ATTRIB(Binding,BINDING);
            DECL_STRING_ATTRIB(Location,LOCATION);
            DECL_STRING_ATTRIB(ResponseLocation,RESPONSELOCATION);
            /** EndpointType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,IndexedEndpointType,EndpointType,SAML 2.0 IndexedEndpointType type);
            DECL_INTEGER_ATTRIB(Index,INDEX);
            DECL_BOOLEAN_ATTRIB(isDefault,ISDEFAULT);
            /** IndexedEndpointType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ArtifactResolutionService,IndexedEndpointType,SAML 2.0 ArtifactResolutionService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SingleLogoutService,EndpointType,SAML 2.0 SingleLogoutService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ManageNameIDService,EndpointType,SAML 2.0 ManageNameIDService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SSODescriptorType,RoleDescriptor,SAML 2.0 SSODescriptorType abstract type);
            DECL_TYPED_CHILDREN(ArtifactResolutionService);
            DECL_TYPED_CHILDREN(SingleLogoutService);
            DECL_TYPED_CHILDREN(ManageNameIDService);
            DECL_TYPED_CHILDREN(NameIDFormat);
            /** SSODescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SingleSignOnService,EndpointType,SAML 2.0 SingleSignOnService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,NameIDMappingService,EndpointType,SAML 2.0 NameIDMappingService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AssertionIDRequestService,EndpointType,SAML 2.0 AssertionIDRequestService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,IDPSSODescriptor,SSODescriptorType,SAML 2.0 IDPSSODescriptor element);
            DECL_BOOLEAN_ATTRIB(WantAuthnRequestsSigned,WANTAUTHNREQUESTSSIGNED);
            DECL_TYPED_CHILDREN(SingleSignOnService);
            DECL_TYPED_CHILDREN(NameIDMappingService);
            DECL_TYPED_CHILDREN(AssertionIDRequestService);
            DECL_TYPED_CHILDREN(AttributeProfile);
            DECL_TYPED_FOREIGN_CHILDREN(Attribute,saml2);
            /** IDPSSODescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ServiceName,localizedNameType,SAML 2.0 ServiceName element);
            DECL_XMLOBJECT_CONTENT(Name);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ServiceDescription,localizedNameType,SAML 2.0 ServiceDescription element);
            DECL_XMLOBJECT_CONTENT(Description);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,RequestedAttribute,saml2::Attribute,SAML 2.0 RequestedAttribute element);
            DECL_BOOLEAN_ATTRIB(isRequired,ISREQUIRED);
            /** RequestedAttributeType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AttributeConsumingService,xmltooling::XMLObject,SAML 2.0 AttributeConsumingService element);
            DECL_INTEGER_ATTRIB(Index,INDEX);
            DECL_BOOLEAN_ATTRIB(isDefault,ISDEFAULT);
            DECL_TYPED_CHILDREN(ServiceName);
            DECL_TYPED_CHILDREN(ServiceDescription);
            DECL_TYPED_CHILDREN(RequestedAttribute);
            /** AttributeConsumingServiceType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AssertionConsumerService,IndexedEndpointType,SAML 2.0 AssertionConsumerService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SPSSODescriptor,SSODescriptorType,SAML 2.0 SPSSODescriptor element);
            DECL_BOOLEAN_ATTRIB(AuthnRequestsSigned,AUTHNREQUESTSSIGNED);
            DECL_BOOLEAN_ATTRIB(WantAssertionsSigned,WANTASSERTIONSSIGNED);
            DECL_TYPED_CHILDREN(AssertionConsumerService);
            DECL_TYPED_CHILDREN(AttributeConsumingService);
            /** SPSSODescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnQueryService,EndpointType,SAML 2.0 AuthnQueryService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnAuthorityDescriptor,RoleDescriptor,SAML 2.0 AuthnAuthorityDescriptor element);
            DECL_TYPED_CHILDREN(AuthnQueryService);
            DECL_TYPED_CHILDREN(AssertionIDRequestService);
            DECL_TYPED_CHILDREN(NameIDFormat);
            /** AuthnAuthorityDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthzService,EndpointType,SAML 2.0 AuthzService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,PDPDescriptor,RoleDescriptor,SAML 2.0 PDPDescriptor element);
            DECL_TYPED_CHILDREN(AuthzService);
            DECL_TYPED_CHILDREN(AssertionIDRequestService);
            DECL_TYPED_CHILDREN(NameIDFormat);
            /** PDPDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AttributeService,EndpointType,SAML 2.0 AttributeService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AttributeAuthorityDescriptor,RoleDescriptor,SAML 2.0 AttributeAuthorityDescriptor element);
            DECL_TYPED_CHILDREN(AttributeService);
            DECL_TYPED_CHILDREN(AssertionIDRequestService);
            DECL_TYPED_CHILDREN(NameIDFormat);
            DECL_TYPED_CHILDREN(AttributeProfile);
            DECL_TYPED_FOREIGN_CHILDREN(Attribute,saml2);
            /** AttributeAuthorityDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT2(SAML_API,AffiliationDescriptor,xmltooling::AttributeExtensibleXMLObject,SignableObject,SAML 2.0 AffiliationDescriptor element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(AffiliationOwnerID,AFFILIATIONOWNERID);
            DECL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL);
            DECL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION);
            DECL_TYPED_FOREIGN_CHILD(Signature,xmlsignature);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILDREN(AffiliateMember);
            DECL_TYPED_CHILDREN(KeyDescriptor);
            /** AffiliationDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT2(SAML_API,EntityDescriptor,xmltooling::AttributeExtensibleXMLObject,SignableObject,SAML 2.0 EntityDescriptor element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(EntityID,ENTITYID);
            DECL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL);
            DECL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION);
            DECL_TYPED_FOREIGN_CHILD(Signature,xmlsignature);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILD(AffiliationDescriptor);
            DECL_TYPED_CHILDREN(RoleDescriptor);
            DECL_TYPED_CHILDREN(IDPSSODescriptor);
            DECL_TYPED_CHILDREN(SPSSODescriptor);
            DECL_TYPED_CHILDREN(AuthnAuthorityDescriptor);
            DECL_TYPED_CHILDREN(AttributeAuthorityDescriptor);
            DECL_TYPED_CHILDREN(PDPDescriptor);
            /** EntityDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,EntitiesDescriptor,SignableObject,SAML 2.0 EntitiesDescriptor element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(Name,NAME);
            DECL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL);
            DECL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION);
            DECL_TYPED_FOREIGN_CHILD(Signature,xmlsignature);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILDREN(EntityDescriptor);
            DECL_TYPED_CHILDREN(EntitiesDescriptor);
            /** EntitiesDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        DECL_SAML2MDOBJECTBUILDER(AdditionalMetadataLocation);
        DECL_SAML2MDOBJECTBUILDER(AffiliateMember);
        DECL_SAML2MDOBJECTBUILDER(AffiliationDescriptor);
        DECL_SAML2MDOBJECTBUILDER(ArtifactResolutionService);
        DECL_SAML2MDOBJECTBUILDER(AssertionConsumerService);
        DECL_SAML2MDOBJECTBUILDER(AssertionIDRequestService);
        DECL_SAML2MDOBJECTBUILDER(AttributeAuthorityDescriptor);
        DECL_SAML2MDOBJECTBUILDER(AttributeConsumingService);
        DECL_SAML2MDOBJECTBUILDER(AttributeProfile);
        DECL_SAML2MDOBJECTBUILDER(AttributeService);
        DECL_SAML2MDOBJECTBUILDER(AuthnAuthorityDescriptor);
        DECL_SAML2MDOBJECTBUILDER(AuthnQueryService);
        DECL_SAML2MDOBJECTBUILDER(AuthzService);
        DECL_SAML2MDOBJECTBUILDER(Company);
        DECL_SAML2MDOBJECTBUILDER(ContactPerson);
        DECL_SAML2MDOBJECTBUILDER(EmailAddress);
        DECL_SAML2MDOBJECTBUILDER(EntitiesDescriptor);
        DECL_SAML2MDOBJECTBUILDER(EntityDescriptor);
        DECL_SAML2MDOBJECTBUILDER(Extensions);
        DECL_SAML2MDOBJECTBUILDER(GivenName);
        DECL_SAML2MDOBJECTBUILDER(IDPSSODescriptor);
        DECL_SAML2MDOBJECTBUILDER(KeyDescriptor);
        DECL_SAML2MDOBJECTBUILDER(ManageNameIDService);
        DECL_SAML2MDOBJECTBUILDER(NameIDFormat);
        DECL_SAML2MDOBJECTBUILDER(NameIDMappingService);
        DECL_SAML2MDOBJECTBUILDER(Organization);
        DECL_SAML2MDOBJECTBUILDER(OrganizationName);
        DECL_SAML2MDOBJECTBUILDER(OrganizationDisplayName);
        DECL_SAML2MDOBJECTBUILDER(OrganizationURL);
        DECL_SAML2MDOBJECTBUILDER(PDPDescriptor);
        DECL_SAML2MDOBJECTBUILDER(RequestedAttribute);
        DECL_SAML2MDOBJECTBUILDER(ServiceDescription);
        DECL_SAML2MDOBJECTBUILDER(ServiceName);
        DECL_SAML2MDOBJECTBUILDER(SingleLogoutService);
        DECL_SAML2MDOBJECTBUILDER(SingleSignOnService);
        DECL_SAML2MDOBJECTBUILDER(SPSSODescriptor);
        DECL_SAML2MDOBJECTBUILDER(SurName);
        DECL_SAML2MDOBJECTBUILDER(TelephoneNumber);

        /**
         * Builder for localizedNameType objects.
         * 
         * This is customized to force the element name to be specified.
         */
        class SAML_API localizedNameTypeBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~localizedNameTypeBuilder() {}
            /** Builder that allows element/type override. */
            virtual localizedNameType* buildObject(
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL
                ) const;
        
            /** Singleton builder. */
            static localizedNameType* buildlocalizedNameType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL) {
                const localizedNameTypeBuilder* b = dynamic_cast<const localizedNameTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(SAMLConstants::SAML20MD_NS,localizedNameType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(SAMLConstants::SAML20MD_NS,localizedNameType::TYPE_NAME,SAMLConstants::SAML20MD_PREFIX);
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for localizedNameType.");
            }
        };

        /**
         * Builder for localizedURIType objects.
         * 
         * This is customized to force the element name to be specified.
         */
        class SAML_API localizedURITypeBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~localizedURITypeBuilder() {}
            /** Builder that allows element/type override. */
            virtual localizedURIType* buildObject(
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL
                ) const;
        
            /** Singleton builder. */
            static localizedURIType* buildlocalizedURIType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL) {
                const localizedURITypeBuilder* b = dynamic_cast<const localizedURITypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(SAMLConstants::SAML20MD_NS,localizedURIType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(SAMLConstants::SAML20MD_NS,localizedURIType::TYPE_NAME,SAMLConstants::SAML20MD_PREFIX);
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for localizedURIType.");
            }
        };

        /**
         * Builder for EndpointType objects.
         * 
         * This is customized to force the element name to be specified.
         */
        class SAML_API EndpointTypeBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~EndpointTypeBuilder() {}
            /** Builder that allows element/type override. */
            virtual EndpointType* buildObject(
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL
                ) const;
        
            /** Singleton builder. */
            static EndpointType* buildEndpointType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL) {
                const EndpointTypeBuilder* b = dynamic_cast<const EndpointTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(SAMLConstants::SAML20MD_NS,EndpointType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(SAMLConstants::SAML20MD_NS,EndpointType::TYPE_NAME,SAMLConstants::SAML20MD_PREFIX);
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for EndpointType.");
            }
        };

        /**
         * Builder for IndexedEndpointType objects.
         * 
         * This is customized to force the element name to be specified.
         */
        class SAML_API IndexedEndpointTypeBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~IndexedEndpointTypeBuilder() {}
            /** Builder that allows element/type override. */
            virtual IndexedEndpointType* buildObject(
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL
                ) const;
        
            /** Singleton builder. */
            static IndexedEndpointType* buildIndexedEndpointType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL) {
                const IndexedEndpointTypeBuilder* b = dynamic_cast<const IndexedEndpointTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(SAMLConstants::SAML20MD_NS,IndexedEndpointType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(SAMLConstants::SAML20MD_NS,IndexedEndpointType::TYPE_NAME,SAMLConstants::SAML20MD_PREFIX);
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for IndexedEndpointType.");
            }
        };

        /**
         * Registers builders and validators for Metadata classes into the runtime.
         */
        void SAML_API registerMetadataClasses();
    };
};

#endif /* __saml2_metadata_h__ */
