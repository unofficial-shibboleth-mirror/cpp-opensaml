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
 * @file saml/saml2/metadata/Metadata.h
 *
 * XMLObjects representing the SAML 2.0 Metadata schema.
 */

#ifndef __saml2_metadata_h__
#define __saml2_metadata_h__

#include <saml/saml2/core/Assertions.h>

#include <ctime>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/Predicates.h>


#define DECL_SAML2MDOBJECTBUILDER(cname) \
    DECL_XMLOBJECTBUILDER(SAML_API,cname,samlconstants::SAML20MD_NS,samlconstants::SAML20MD_PREFIX)

namespace xmltooling {
    class XMLTOOL_API Credential;
    class XMLTOOL_API CredentialResolver;
}

namespace xmlencryption {
    class XMLTOOL_API EncryptionMethod;
};

namespace opensaml {

    /**
     * @namespace opensaml::saml2md
     * SAML 2.0 metadata namespace
     */
    namespace saml2md {

        class SAML_API DigestMethod;
        class SAML_API SigningMethod;

        /**
         * Base class for metadata objects that feature a cacheDuration attribute.
         */
        class SAML_API CacheableSAMLObject : public virtual xmltooling::XMLObject
        {
        protected:
            CacheableSAMLObject() {}
        public:
            ~CacheableSAMLObject() {}
            DECL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION);
        };

        /**
         * Base class for metadata objects that feature a validUntil attribute.
         */
        class SAML_API TimeBoundSAMLObject : public virtual xmltooling::XMLObject
        {
        protected:
            TimeBoundSAMLObject() {}
        public:
            ~TimeBoundSAMLObject() {}
            DECL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL);
            /** Returns true iff the object is valid at the current time. */
            bool isValid() const {
                return time(nullptr) <= getValidUntilEpoch();
            }
            /**
             * Returns true iff the object is valid at the supplied time.
             *
             * @param t the time to check against
             */
            bool isValid(time_t t) const {
                return t <= getValidUntilEpoch();
            }
        };

        DECL_XMLOBJECT_SIMPLE(SAML_API,AffiliateMember,ID,SAML 2.0 AffiliateMember element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,AttributeProfile,ProfileURI,SAML 2.0 AttributeProfile element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,Company,Name,SAML 2.0 Company element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,EmailAddress,Address,SAML 2.0 EmailAddress element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,GivenName,Name,SAML 2.0 GivenName element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,NameIDFormat,Format,SAML 2.0 NameIDFormat element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,SurName,Name,SAML 2.0 SurName element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,TelephoneNumber,Number,SAML 2.0 TelephoneNumber element);

        DECL_XMLOBJECT_SIMPLE(SAML_API,ActionNamespace,Namespace,SAML 2.0 Metadata Extension ActionNamespace element);

        BEGIN_XMLOBJECT(SAML_API,localizedNameType,xmltooling::XMLObject,SAML 2.0 localizedNameType type);
            /** xml:lang attribute name. */
            static const XMLCh LANG_ATTRIB_NAME[];

            /**
             * Sets the xml:lang attribute.
             *
             * @param Lang  the value to set
             */
            virtual void setLang(const XMLCh* Lang)=0;

            /** localizedNameType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,localizedURIType,xmltooling::XMLObject,SAML 2.0 localizedURIType type);
            /** xml:lang attribute name. */
            static const XMLCh LANG_ATTRIB_NAME[];

            /**
             * Sets the xml:lang attribute.
             *
             * @param Lang  the value to set
             */
            virtual void setLang(const XMLCh* Lang)=0;

            /** localizedURIType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,OrganizationName,localizedNameType,SAML 2.0 OrganizationName element);
            DECL_SIMPLE_CONTENT(Name);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,OrganizationDisplayName,localizedNameType,SAML 2.0 OrganizationDisplayName element);
            DECL_SIMPLE_CONTENT(Name);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,OrganizationURL,localizedURIType,SAML 2.0 OrganizationURL element);
            DECL_SIMPLE_CONTENT(URL);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Extensions,xmltooling::ElementExtensibleXMLObject,SAML 2.0 Extensions element);
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

        BEGIN_XMLOBJECT(SAML_API,AdditionalMetadataLocation,xmltooling::XMLObject,SAML 2.0 AdditionalMetadataLocation element);
            DECL_STRING_ATTRIB(Namespace,NAMESPACE);
            DECL_SIMPLE_CONTENT(Location);
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

        BEGIN_XMLOBJECT4(SAML_API,RoleDescriptor,xmltooling::AttributeExtensibleXMLObject,SignableObject,
                CacheableSAMLObject,TimeBoundSAMLObject,SAML 2.0 RoleDescriptor abstract element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(ProtocolSupportEnumeration,PROTOCOLSUPPORTENUMERATION);
            /** Searches the ProtocolSupportEnumeration attribute for the indicated protocol. */
            virtual bool hasSupport(const XMLCh* protocol) const=0;
            /** Adds the indicated protocol to the ProtocolSupportEnumeration attribute. */
            virtual void addSupport(const XMLCh* protocol)=0;
            DECL_STRING_ATTRIB(ErrorURL,ERRORURL);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILDREN(KeyDescriptor);
            DECL_TYPED_CHILD(Organization);
            DECL_TYPED_CHILDREN(ContactPerson);
            /** Returns the first digest method supported by the role and the underlying implementation, if any. */
            virtual const DigestMethod* getDigestMethod() const;
            /** Returns the first signing method supported by the role and the underlying implementation, if any, along with a matching credential. */
            virtual std::pair<const SigningMethod*,const xmltooling::Credential*> getSigningMethod(
                const xmltooling::CredentialResolver& resolver, xmltooling::CredentialCriteria& cc
                ) const;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT2(SAML_API,RoleDescriptorType,RoleDescriptor,xmltooling::ElementExtensibleXMLObject,SAML 2.0 RoleDescriptor extension);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,EndpointType,xmltooling::ElementProxy,SAML 2.0 EndpointType type);
            DECL_STRING_ATTRIB(Binding,BINDING);
            DECL_STRING_ATTRIB(Location,LOCATION);
            DECL_STRING_ATTRIB(ResponseLocation,RESPONSELOCATION);
            /** EndpointType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,IndexedEndpointType,EndpointType,SAML 2.0 IndexedEndpointType type);
            DECL_INTEGER_ATTRIB(Index,INDEX);
            DECL_BOOLEAN_ATTRIB(isDefault,ISDEFAULT,false);
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
            DECL_BOOLEAN_ATTRIB(WantAuthnRequestsSigned,WANTAUTHNREQUESTSSIGNED,false);
            DECL_TYPED_CHILDREN(SingleSignOnService);
            DECL_TYPED_CHILDREN(NameIDMappingService);
            DECL_TYPED_CHILDREN(AssertionIDRequestService);
            DECL_TYPED_CHILDREN(AttributeProfile);
            DECL_TYPED_FOREIGN_CHILDREN(Attribute,saml2);
            /** IDPSSODescriptorType local name */
            static const XMLCh TYPE_NAME[];
            DECL_ELEMENT_QNAME;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ServiceName,localizedNameType,SAML 2.0 ServiceName element);
            DECL_SIMPLE_CONTENT(Name);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ServiceDescription,localizedNameType,SAML 2.0 ServiceDescription element);
            DECL_SIMPLE_CONTENT(Description);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,RequestedAttribute,saml2::Attribute,SAML 2.0 RequestedAttribute element);
            DECL_BOOLEAN_ATTRIB(isRequired,ISREQUIRED,false);
            /** RequestedAttributeType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AttributeConsumingService,xmltooling::XMLObject,SAML 2.0 AttributeConsumingService element);
            DECL_INTEGER_ATTRIB(Index,INDEX);
            DECL_BOOLEAN_ATTRIB(isDefault,ISDEFAULT,false);
            DECL_TYPED_CHILDREN(ServiceName);
            DECL_TYPED_CHILDREN(ServiceDescription);
            DECL_TYPED_CHILDREN(RequestedAttribute);
            /** AttributeConsumingServiceType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AssertionConsumerService,IndexedEndpointType,SAML 2.0 AssertionConsumerService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SPSSODescriptor,SSODescriptorType,SAML 2.0 SPSSODescriptor element);
            DECL_BOOLEAN_ATTRIB(AuthnRequestsSigned,AUTHNREQUESTSSIGNED,false);
            DECL_BOOLEAN_ATTRIB(WantAssertionsSigned,WANTASSERTIONSSIGNED,false);
            DECL_TYPED_CHILDREN(AssertionConsumerService);
            DECL_TYPED_CHILDREN(AttributeConsumingService);
            /** SPSSODescriptorType local name */
            static const XMLCh TYPE_NAME[];
            DECL_ELEMENT_QNAME;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnQueryService,EndpointType,SAML 2.0 AuthnQueryService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnAuthorityDescriptor,RoleDescriptor,SAML 2.0 AuthnAuthorityDescriptor element);
            DECL_TYPED_CHILDREN(AuthnQueryService);
            DECL_TYPED_CHILDREN(AssertionIDRequestService);
            DECL_TYPED_CHILDREN(NameIDFormat);
            /** AuthnAuthorityDescriptorType local name */
            static const XMLCh TYPE_NAME[];
            DECL_ELEMENT_QNAME;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthzService,EndpointType,SAML 2.0 AuthzService element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,PDPDescriptor,RoleDescriptor,SAML 2.0 PDPDescriptor element);
            DECL_TYPED_CHILDREN(AuthzService);
            DECL_TYPED_CHILDREN(AssertionIDRequestService);
            DECL_TYPED_CHILDREN(NameIDFormat);
            /** PDPDescriptorType local name */
            static const XMLCh TYPE_NAME[];
            DECL_ELEMENT_QNAME;
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
            DECL_ELEMENT_QNAME;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,QueryDescriptorType,RoleDescriptor,SAML 2.0 QueryDescriptorType abstract type);
            DECL_BOOLEAN_ATTRIB(WantAssertionsSigned,WANTASSERTIONSSIGNED,false);
            DECL_TYPED_CHILDREN(NameIDFormat);
            /** QueryDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnQueryDescriptorType,QueryDescriptorType,SAML 2.0 AuthnQueryDescriptorType extension type);
            /** AuthnQueryDescriptorType local name */
            static const XMLCh TYPE_NAME[];
            DECL_TYPE_QNAME;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AttributeQueryDescriptorType,QueryDescriptorType,SAML 2.0 AttributeQueryDescriptorType extension type);
            DECL_TYPED_CHILDREN(AttributeConsumingService);
            /** AttributeQueryDescriptorType local name */
            static const XMLCh TYPE_NAME[];
            DECL_TYPE_QNAME;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthzDecisionQueryDescriptorType,QueryDescriptorType,SAML 2.0 AuthzDecisionQueryDescriptorType extension type);
            DECL_TYPED_CHILDREN(ActionNamespace);
            /** AuthzDecisionQueryDescriptorType local name */
            static const XMLCh TYPE_NAME[];
            DECL_TYPE_QNAME;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT4(SAML_API,AffiliationDescriptor,xmltooling::AttributeExtensibleXMLObject,SignableObject,
                CacheableSAMLObject,TimeBoundSAMLObject,SAML 2.0 AffiliationDescriptor element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(AffiliationOwnerID,AFFILIATIONOWNERID);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILDREN(AffiliateMember);
            DECL_TYPED_CHILDREN(KeyDescriptor);
            /** AffiliationDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT4(SAML_API,EntityDescriptor,xmltooling::AttributeExtensibleXMLObject,SignableObject,
                CacheableSAMLObject,TimeBoundSAMLObject,SAML 2.0 EntityDescriptor element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(EntityID,ENTITYID);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILD(AffiliationDescriptor);
            DECL_TYPED_CHILDREN(RoleDescriptor);
            DECL_TYPED_CHILDREN(IDPSSODescriptor);
            DECL_TYPED_CHILDREN(SPSSODescriptor);
            DECL_TYPED_CHILDREN(AuthnAuthorityDescriptor);
            DECL_TYPED_CHILDREN(AttributeAuthorityDescriptor);
            DECL_TYPED_CHILDREN(PDPDescriptor);
            DECL_TYPED_CHILDREN(AuthnQueryDescriptorType);
            DECL_TYPED_CHILDREN(AttributeQueryDescriptorType);
            DECL_TYPED_CHILDREN(AuthzDecisionQueryDescriptorType);
            DECL_TYPED_CHILD(Organization);
            DECL_TYPED_CHILDREN(ContactPerson);
            DECL_TYPED_CHILDREN(AdditionalMetadataLocation);
            /** Finds an arbitrary role type supporting a given protocol. */
            virtual const RoleDescriptor* getRoleDescriptor(const xmltooling::QName& qname, const XMLCh* protocol) const=0;
            /** EntityDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT3(SAML_API,EntitiesDescriptor,SignableObject,CacheableSAMLObject,
                TimeBoundSAMLObject,SAML 2.0 EntitiesDescriptor element);
            DECL_STRING_ATTRIB(ID,ID);
            DECL_STRING_ATTRIB(Name,NAME);
            DECL_TYPED_CHILD(Extensions);
            DECL_TYPED_CHILDREN(EntityDescriptor);
            DECL_TYPED_CHILDREN(EntitiesDescriptor);
            /** EntitiesDescriptorType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        // Known Metadata Extensions

        DECL_XMLOBJECT_SIMPLE(SAML_API,SourceID,ID,SAML 1.x Metadata Profile SourceID element);

        BEGIN_XMLOBJECT(SAML_API,DiscoveryResponse,IndexedEndpointType,Identity Provider Discovery Protocol DiscoveryResponse element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,RequestInitiator,EndpointType,Service Provider Request Initiation RequestInitiator element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,EntityAttributes,xmltooling::XMLObject,SAML Metadata Extension for Entity Attributes element);
            DECL_TYPED_FOREIGN_CHILDREN(Attribute,saml2);
            DECL_TYPED_FOREIGN_CHILDREN(Assertion,saml2);
            /** EntityAttributesType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,DigestMethod,xmltooling::ElementExtensibleXMLObject,SAML Metadata Extension for Algorithm Support DigestMethod element);
            DECL_STRING_ATTRIB(Algorithm,ALGORITHM);
            /** DigestMethodType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SigningMethod,xmltooling::ElementExtensibleXMLObject,SAML Metadata Extension for Algorithm Support SigningMethod element);
            DECL_STRING_ATTRIB(Algorithm,ALGORITHM);
            DECL_INTEGER_ATTRIB(MinKeySize,MINKEYSIZE);
            DECL_INTEGER_ATTRIB(MaxKeySize,MAXKEYSIZE);
            /** SigningMethodType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,DisplayName,localizedNameType,SAML Metadata Extension for Login UI DisplayName element);
            DECL_SIMPLE_CONTENT(Name);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Description,localizedNameType,SAML Metadata Extension for Login UI Description element);
            DECL_SIMPLE_CONTENT(Description);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Keywords,xmltooling::XMLObject,SAML Metadata Extension for Login UI Keywords element);
            /** xml:lang attribute name. */
            static const XMLCh LANG_ATTRIB_NAME[];

            /**
             * Sets the xml:lang attribute.
             *
             * @param Lang  the value to set
             */
            virtual void setLang(const XMLCh* Lang)=0;

            DECL_SIMPLE_CONTENT(Values);
            /** KeywordsType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Logo,xmltooling::XMLObject,SAML Metadata Extension for Login UI Logo element);
            /** xml:lang attribute name. */
            static const XMLCh LANG_ATTRIB_NAME[];

            /**
             * Sets the xml:lang attribute.
             *
             * @param Lang  the value to set
             */
            virtual void setLang(const XMLCh* Lang)=0;

            DECL_INTEGER_ATTRIB(Height,HEIGHT);
            DECL_INTEGER_ATTRIB(Width,WIDTH);
            DECL_SIMPLE_CONTENT(URL);
            /** LogoType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,InformationURL,localizedURIType,SAML Metadata Extension for Login UI InformationURL element);
            DECL_SIMPLE_CONTENT(URL);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,PrivacyStatementURL,localizedURIType,SAML Metadata Extension for Login UI PrivacyStatementURL element);
            DECL_SIMPLE_CONTENT(URL);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,UIInfo,xmltooling::ElementExtensibleXMLObject,SAML Metadata Extension for Login UI UIInfo element);
            DECL_TYPED_CHILDREN(DisplayName);
            DECL_TYPED_CHILDREN(Description);
			DECL_TYPED_CHILDREN(Keywords);
            DECL_TYPED_CHILDREN(Logo);
            DECL_TYPED_CHILDREN(InformationURL);
            DECL_TYPED_CHILDREN(PrivacyStatementURL);
            /** UIInfoType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        DECL_XMLOBJECT_SIMPLE(SAML_API,IPHint,Hint,SAML Metadata Extension for Login UI IPHint element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,DomainHint,Hint,SAML Metadata Extension for Login UI DomainHint element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,GeolocationHint,Hint,SAML Metadata Extension for Login UI GeolocationHint element);

        BEGIN_XMLOBJECT(SAML_API,DiscoHints,xmltooling::ElementExtensibleXMLObject,SAML Metadata Extension for Login UI DiscoHints element);
            DECL_TYPED_CHILDREN(IPHint);
            DECL_TYPED_CHILDREN(DomainHint);
            DECL_TYPED_CHILDREN(GeolocationHint);
            /** DiscoHintsType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API, RegistrationPolicy, localizedURIType, SAML Metadata Extension for RPI RegistrationPolicy element);
            DECL_SIMPLE_CONTENT(URL);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,RegistrationInfo,xmltooling::ElementProxy,SAML Metadata Extension for RPI RegistrationInfo element);
            DECL_STRING_ATTRIB(RegistrationAuthority,REGAUTHORITY);
            DECL_DATETIME_ATTRIB(RegistrationInstant,REGINSTANT);
            DECL_TYPED_CHILDREN(RegistrationPolicy);
            /** RegistrationInfoType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Publication,xmltooling::XMLObject,SAML Metadata Extension for RPI Publication element);
            DECL_STRING_ATTRIB(Publisher,PUBLISHER);
            DECL_DATETIME_ATTRIB(CreationInstant,CREATIONINSTANT);
            DECL_STRING_ATTRIB(PublicationID,PUBLICATIONID);
            /** PublicationType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,PublicationPath,xmltooling::XMLObject,SAML Metadata Extension for RPI PublicationPath element);
            DECL_TYPED_CHILDREN(Publication);
            /** PublicationPathType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API, UsagePolicy, localizedURIType, SAML Metadata Extension for RPI UsagePolicy element);
            DECL_SIMPLE_CONTENT(URL);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,PublicationInfo,xmltooling::ElementProxy,SAML Metadata Extension for RPI PublicationInfo element);
			DECL_STRING_ATTRIB(Publisher,PUBLISHER);
			DECL_DATETIME_ATTRIB(CreationInstant,CREATIONINSTANT);
			DECL_STRING_ATTRIB(PublicationID,PUBLICATIONID);
			DECL_TYPED_CHILDREN(UsagePolicy);
			/** PublicationInfoType local name */
			static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        /**
         * Predicate to test a role for validity and protocol support.
         */
        class isValidForProtocol
        {
        public:
            /**
             * Constructor.
             *
             * @param protocol  support constant to test for
             */
            isValidForProtocol(const XMLCh* protocol) : m_time(time(nullptr)), m_protocol(protocol) {
            }

            /**
             * Returns true iff the supplied role is valid now and supports the right protocol.
             *
             * @param role  role to test
             * @return  result of predicate
             */
            bool operator()(const RoleDescriptor* role) const {
                return role ? (role->isValid(m_time) && role->hasSupport(m_protocol)) : false;
            }

        private:
            time_t m_time;
            const XMLCh* m_protocol;
        };

        /**
         * Predicate to test a role for type equivalence, validity, and protocol support.
         */
        class ofTypeValidForProtocol : public isValidForProtocol, public xmltooling::hasSchemaType
        {
        public:
            /**
             * Constructor.
             *
             * @param q         schema type to test for
             * @param protocol  support constant to test for
             */
            ofTypeValidForProtocol(const xmltooling::QName& q, const XMLCh* protocol)
                : isValidForProtocol(protocol), xmltooling::hasSchemaType(q)  {
            }

            /**
             * Returns true iff the supplied role is of the right type, valid now, and supports the right protocol.
             *
             * @param role  role to test
             * @return  result of predicate
             */
            bool operator()(const RoleDescriptor* role) const {
                return xmltooling::hasSchemaType::operator()(role) && isValidForProtocol::operator()(role);
            }
        };

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

        DECL_XMLOBJECTBUILDER(SAML_API,ActionNamespace,samlconstants::SAML20MD_QUERY_EXT_NS,samlconstants::SAML20MD_QUERY_EXT_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,SourceID,samlconstants::SAML1MD_NS,samlconstants::SAML1MD_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,DiscoveryResponse,samlconstants::IDP_DISCOVERY_PROTOCOL_NS,samlconstants::IDP_DISCOVERY_PROTOCOL_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,RequestInitiator,samlconstants::SP_REQUEST_INIT_NS,samlconstants::SP_REQUEST_INIT_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,EntityAttributes,samlconstants::SAML20MD_ENTITY_ATTRIBUTE_NS,samlconstants::SAML20MD_ENTITY_ATTRIBUTE_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,DigestMethod,samlconstants::SAML20MD_ALGSUPPORT_NS,samlconstants::SAML20MD_ALGSUPPORT_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,SigningMethod,samlconstants::SAML20MD_ALGSUPPORT_NS,samlconstants::SAML20MD_ALGSUPPORT_PREFIX);

        DECL_XMLOBJECTBUILDER(SAML_API,UIInfo,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,DisplayName,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,Description,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
		DECL_XMLOBJECTBUILDER(SAML_API,Keywords,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,Logo,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,InformationURL,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,PrivacyStatementURL,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,DiscoHints,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,IPHint,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,DomainHint,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API,GeolocationHint,samlconstants::SAML20MD_UI_NS,samlconstants::SAML20MD_UI_PREFIX);

        DECL_XMLOBJECTBUILDER(SAML_API, RegistrationInfo, samlconstants::SAML20MD_RPI_NS, samlconstants::SAML20MD_RPI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API, RegistrationPolicy, samlconstants::SAML20MD_RPI_NS, samlconstants::SAML20MD_RPI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API, Publication, samlconstants::SAML20MD_RPI_NS, samlconstants::SAML20MD_RPI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API, PublicationPath, samlconstants::SAML20MD_RPI_NS, samlconstants::SAML20MD_RPI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API, PublicationInfo, samlconstants::SAML20MD_RPI_NS, samlconstants::SAML20MD_RPI_PREFIX);
        DECL_XMLOBJECTBUILDER(SAML_API, UsagePolicy, samlconstants::SAML20MD_RPI_NS, samlconstants::SAML20MD_RPI_PREFIX);

        /**
         * Builder for localizedNameType objects.
         *
         * This is customized to force the element name to be specified.
         */
        class SAML_API localizedNameTypeBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~localizedNameTypeBuilder() {}
            /** Builder that allows element/type override. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual localizedNameType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static localizedNameType* buildlocalizedNameType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr) {
                const localizedNameTypeBuilder* b = dynamic_cast<const localizedNameTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_NS,localizedNameType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(samlconstants::SAML20MD_NS,localizedNameType::TYPE_NAME,samlconstants::SAML20MD_PREFIX);
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
#else
                    return dynamic_cast<localizedNameType*>(b->buildObject(nsURI, localName, prefix, &schemaType));
#endif
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
#ifdef HAVE_COVARIANT_RETURNS
            virtual localizedURIType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static localizedURIType* buildlocalizedURIType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr) {
                const localizedURITypeBuilder* b = dynamic_cast<const localizedURITypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_NS,localizedURIType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(samlconstants::SAML20MD_NS,localizedURIType::TYPE_NAME,samlconstants::SAML20MD_PREFIX);
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
#else
                    return dynamic_cast<localizedURIType*>(b->buildObject(nsURI, localName, prefix, &schemaType));
#endif
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
#ifdef HAVE_COVARIANT_RETURNS
            virtual EndpointType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static EndpointType* buildEndpointType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr) {
                const EndpointTypeBuilder* b = dynamic_cast<const EndpointTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_NS,EndpointType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(samlconstants::SAML20MD_NS,EndpointType::TYPE_NAME,samlconstants::SAML20MD_PREFIX);
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
#else
                    return dynamic_cast<EndpointType*>(b->buildObject(nsURI, localName, prefix, &schemaType));
#endif
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
#ifdef HAVE_COVARIANT_RETURNS
            virtual IndexedEndpointType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static IndexedEndpointType* buildIndexedEndpointType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr) {
                const IndexedEndpointTypeBuilder* b = dynamic_cast<const IndexedEndpointTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_NS,IndexedEndpointType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(samlconstants::SAML20MD_NS,IndexedEndpointType::TYPE_NAME,samlconstants::SAML20MD_PREFIX);
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
#else
                    return dynamic_cast<IndexedEndpointType*>(b->buildObject(nsURI, localName, prefix, &schemaType));
#endif
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for IndexedEndpointType.");
            }
        };

        /**
         * Builder for RoleDescriptor extension objects.
         *
         * This is customized to force the schema type to be specified.
         */
        class SAML_API RoleDescriptorBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~RoleDescriptorBuilder() {}
            /** Builder that allows element/type override. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual RoleDescriptor* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static RoleDescriptor* buildRoleDescriptor(const xmltooling::QName& schemaType) {
                const RoleDescriptorBuilder* b = dynamic_cast<const RoleDescriptorBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_NS,RoleDescriptor::LOCAL_NAME))
                    );
                if (b) {
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject(samlconstants::SAML20MD_NS, RoleDescriptor::LOCAL_NAME, samlconstants::SAML20MD_PREFIX, &schemaType);
#else
                    return dynamic_cast<RoleDescriptor*>(b->buildObject(samlconstants::SAML20MD_NS, RoleDescriptor::LOCAL_NAME, samlconstants::SAML20MD_PREFIX, &schemaType));
#endif
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for RoleDescriptor.");
            }
        };

        /**
         * Builder for AuthnQueryDescriptorType objects.
         *
         * This is customized to return a RoleDescriptor element with an
         * xsi:type of AuthnQueryDescriptorType.
         */
        class SAML_API AuthnQueryDescriptorTypeBuilder : public xmltooling::ConcreteXMLObjectBuilder {
        public:
            virtual ~AuthnQueryDescriptorTypeBuilder() {}
            /** Default builder. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual AuthnQueryDescriptorType* buildObject() const {
#else
            virtual xmltooling::XMLObject* buildObject() const {
#endif
                xmltooling::QName schemaType(
                    samlconstants::SAML20MD_QUERY_EXT_NS,AuthnQueryDescriptorType::TYPE_NAME,samlconstants::SAML20MD_QUERY_EXT_PREFIX
                    );
                return buildObject(
                    samlconstants::SAML20MD_NS,AuthnQueryDescriptorType::LOCAL_NAME,samlconstants::SAML20MD_PREFIX,&schemaType
                    );
            }
            /** Builder that allows element/type override. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual AuthnQueryDescriptorType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static AuthnQueryDescriptorType* buildAuthnQueryDescriptorType() {
                const AuthnQueryDescriptorTypeBuilder* b = dynamic_cast<const AuthnQueryDescriptorTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_QUERY_EXT_NS,AuthnQueryDescriptorType::TYPE_NAME))
                    );
                if (b) {
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject();
#else
                    return dynamic_cast<AuthnQueryDescriptorType*>(b->buildObject());
#endif
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for AuthnQueryDescriptorType.");
            }
        };

        /**
         * Builder for AttributeQueryDescriptorType objects.
         *
         * This is customized to return a RoleDescriptor element with an
         * xsi:type of AttributeQueryDescriptorType.
         */
        class SAML_API AttributeQueryDescriptorTypeBuilder : public xmltooling::ConcreteXMLObjectBuilder {
        public:
            virtual ~AttributeQueryDescriptorTypeBuilder() {}
            /** Default builder. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual AttributeQueryDescriptorType* buildObject() const {
#else
            virtual xmltooling::XMLObject* buildObject() const {
#endif
                xmltooling::QName schemaType(
                    samlconstants::SAML20MD_QUERY_EXT_NS,AttributeQueryDescriptorType::TYPE_NAME,samlconstants::SAML20MD_QUERY_EXT_PREFIX
                    );
                return buildObject(
                    samlconstants::SAML20MD_NS,AttributeQueryDescriptorType::LOCAL_NAME,samlconstants::SAML20MD_PREFIX,&schemaType
                    );
            }
            /** Builder that allows element/type override. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual AttributeQueryDescriptorType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static AttributeQueryDescriptorType* buildAttributeQueryDescriptorType() {
                const AttributeQueryDescriptorTypeBuilder* b = dynamic_cast<const AttributeQueryDescriptorTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_QUERY_EXT_NS,AttributeQueryDescriptorType::TYPE_NAME))
                    );
                if (b) {
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject();
#else
                    return dynamic_cast<AttributeQueryDescriptorType*>(b->buildObject());
#endif
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for AttributeQueryDescriptorType.");
            }
        };

        /**
         * Builder for AuthzDecisionQueryDescriptorType objects.
         *
         * This is customized to return a RoleDescriptor element with an
         * xsi:type of AuthzDecisionQueryDescriptorType.
         */
        class SAML_API AuthzDecisionQueryDescriptorTypeBuilder : public xmltooling::ConcreteXMLObjectBuilder {
        public:
            virtual ~AuthzDecisionQueryDescriptorTypeBuilder() {}
            /** Default builder. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual AuthzDecisionQueryDescriptorType* buildObject() const {
#else
            virtual xmltooling::XMLObject* buildObject() const {
#endif
                xmltooling::QName schemaType(
                    samlconstants::SAML20MD_QUERY_EXT_NS,AuthzDecisionQueryDescriptorType::TYPE_NAME,samlconstants::SAML20MD_QUERY_EXT_PREFIX
                    );
                return buildObject(
                    samlconstants::SAML20MD_NS,AuthzDecisionQueryDescriptorType::LOCAL_NAME,samlconstants::SAML20MD_PREFIX,&schemaType
                    );
            }
            /** Builder that allows element/type override. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual AuthzDecisionQueryDescriptorType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const xmltooling::QName* schemaType=nullptr
                ) const;

            /** Singleton builder. */
            static AuthzDecisionQueryDescriptorType* buildAuthzDecisionQueryDescriptorType() {
                const AuthzDecisionQueryDescriptorTypeBuilder* b = dynamic_cast<const AuthzDecisionQueryDescriptorTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_QUERY_EXT_NS,AuthzDecisionQueryDescriptorType::TYPE_NAME))
                    );
                if (b) {
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject();
#else
                    return dynamic_cast<AuthzDecisionQueryDescriptorType*>(b->buildObject());
#endif
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for AuthzDecisionQueryDescriptorType.");
            }
        };

        /**
         * Registers builders and validators for SAML 2.0 Metadata classes into the runtime.
         */
        void SAML_API registerMetadataClasses();
    };
};

#endif /* __saml2_metadata_h__ */
