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
 * MetadataImpl.cpp
 *
 * Implementation classes for SAML 2.0 Metadata schema.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/metadata/Metadata.h"
#include "signature/ContentReference.h"

#include <xmltooling/AbstractComplexElement.h>
#include <xmltooling/AbstractSimpleElement.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/encryption/Encryption.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/XMLHelper.h>

#include <ctime>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/if.hpp>
#include <boost/lambda/lambda.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/framework/XSECDefs.hpp>

using namespace samlconstants;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;
using xmlconstants::XMLSIG_NS;
using xmlconstants::XML_BOOL_NULL;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {
    namespace saml2md {

        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AffiliateMember);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AttributeProfile);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,Company);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,EmailAddress);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,GivenName);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,NameIDFormat);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,SurName);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,TelephoneNumber);

        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,ActionNamespace);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,SourceID);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,IPHint);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,DomainHint);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,GeolocationHint);

        class SAML_DLLLOCAL localizedNameTypeImpl : public virtual localizedNameType,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Lang=nullptr;
                m_LangPrefix=nullptr;
            }

        protected:
            localizedNameTypeImpl() {
                init();
            }

        public:
            virtual ~localizedNameTypeImpl() {
                XMLString::release(&m_Lang);
                XMLString::release(&m_LangPrefix);
            }

            localizedNameTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            localizedNameTypeImpl(const localizedNameTypeImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
            }

            void _clone(const localizedNameTypeImpl& src) {
                IMPL_CLONE_FOREIGN_ATTRIB(Lang);
            }

            IMPL_XMLOBJECT_CLONE_EX(localizedNameType);
            IMPL_XMLOBJECT_FOREIGN_ATTRIB(Lang,XMLCh);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                if (m_Lang && *m_Lang) {
                    DOMAttr* attr=domElement->getOwnerDocument()->createAttributeNS(xmlconstants::XML_NS, LANG_ATTRIB_NAME);
                    if (m_LangPrefix && *m_LangPrefix)
                        attr->setPrefix(m_LangPrefix);
                    else
                        attr->setPrefix(xmlconstants::XML_PREFIX);
                    attr->setNodeValue(m_Lang);
                    domElement->setAttributeNodeNS(attr);
                }
            }

            void processAttribute(const DOMAttr* attribute) {
                if (XMLHelper::isNodeNamed(attribute, xmlconstants::XML_NS, LANG_ATTRIB_NAME)) {
                    setLang(attribute->getValue());
                    const XMLCh* temp = attribute->getPrefix();
                    if (temp && *temp && !XMLString::equals(temp, xmlconstants::XML_NS))
                        m_LangPrefix = XMLString::replicate(temp);
                    return;
                }
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL localizedURITypeImpl : public virtual localizedURIType,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Lang=nullptr;
                m_LangPrefix=nullptr;
            }

        protected:
            localizedURITypeImpl() {
                init();
            }

        public:
            virtual ~localizedURITypeImpl() {
                XMLString::release(&m_Lang);
                XMLString::release(&m_LangPrefix);
            }

            localizedURITypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            localizedURITypeImpl(const localizedURITypeImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
            }

            void _clone(const localizedURITypeImpl& src) {
                IMPL_CLONE_FOREIGN_ATTRIB(Lang);
            }

            IMPL_XMLOBJECT_CLONE_EX(localizedURIType);
            IMPL_XMLOBJECT_FOREIGN_ATTRIB(Lang,XMLCh);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                if (m_Lang && *m_Lang) {
                    DOMAttr* attr=domElement->getOwnerDocument()->createAttributeNS(xmlconstants::XML_NS, LANG_ATTRIB_NAME);
                    if (m_LangPrefix && *m_LangPrefix)
                        attr->setPrefix(m_LangPrefix);
                    else
                        attr->setPrefix(xmlconstants::XML_PREFIX);
                    attr->setNodeValue(m_Lang);
                    domElement->setAttributeNodeNS(attr);
                }
            }

            void processAttribute(const DOMAttr* attribute) {
                if (XMLHelper::isNodeNamed(attribute, xmlconstants::XML_NS, LANG_ATTRIB_NAME)) {
                    setLang(attribute->getValue());
                    const XMLCh* temp = attribute->getPrefix();
                    if (temp && *temp && !XMLString::equals(temp, xmlconstants::XML_NS))
                        m_LangPrefix = XMLString::replicate(temp);
                    return;
                }
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL OrganizationNameImpl : public virtual OrganizationName, public localizedNameTypeImpl
        {
        public:
            virtual ~OrganizationNameImpl() {}

            OrganizationNameImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            OrganizationNameImpl(const OrganizationNameImpl& src) : AbstractXMLObject(src), localizedNameTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(OrganizationName);
        };

        class SAML_DLLLOCAL OrganizationDisplayNameImpl : public virtual OrganizationDisplayName, public localizedNameTypeImpl
        {
        public:
            virtual ~OrganizationDisplayNameImpl() {}

            OrganizationDisplayNameImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            OrganizationDisplayNameImpl(const OrganizationDisplayNameImpl& src) : AbstractXMLObject(src), localizedNameTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(OrganizationDisplayName);
        };

        class SAML_DLLLOCAL OrganizationURLImpl : public virtual OrganizationURL, public localizedURITypeImpl
        {
        public:
            virtual ~OrganizationURLImpl() {}

            OrganizationURLImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            OrganizationURLImpl(const OrganizationURLImpl& src) : AbstractXMLObject(src), localizedURITypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(OrganizationURL);
        };

        class SAML_DLLLOCAL ServiceNameImpl : public virtual ServiceName, public localizedNameTypeImpl
        {
        public:
            virtual ~ServiceNameImpl() {}

            ServiceNameImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            ServiceNameImpl(const ServiceNameImpl& src) : AbstractXMLObject(src), localizedNameTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(ServiceName);
        };

        class SAML_DLLLOCAL ServiceDescriptionImpl : public virtual ServiceDescription, public localizedNameTypeImpl
        {
        public:
            virtual ~ServiceDescriptionImpl() {}

            ServiceDescriptionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            ServiceDescriptionImpl(const ServiceDescriptionImpl& src) : AbstractXMLObject(src), localizedNameTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(ServiceDescription);
        };

        class SAML_DLLLOCAL ExtensionsImpl : public virtual Extensions,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~ExtensionsImpl() {}

            ExtensionsImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            ExtensionsImpl(const ExtensionsImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                IMPL_CLONE_XMLOBJECT_CHILDREN(UnknownXMLObject);
            }

            IMPL_XMLOBJECT_CLONE(Extensions);
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAML20MD_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }

                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL OrganizationImpl : public virtual Organization,
            public AbstractComplexElement,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            list<XMLObject*>::iterator m_pos_OrganizationDisplayName;
            list<XMLObject*>::iterator m_pos_OrganizationURL;

            void init() {
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_Extensions=nullptr;
                m_pos_Extensions=m_children.begin();
                m_pos_OrganizationDisplayName=m_pos_Extensions;
                ++m_pos_OrganizationDisplayName;
                m_pos_OrganizationURL=m_pos_OrganizationDisplayName;
                ++m_pos_OrganizationURL;
            }

        public:
            virtual ~OrganizationImpl() {}

            OrganizationImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            OrganizationImpl(const OrganizationImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src),
                        AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_TYPED_CHILD(Extensions);
                IMPL_CLONE_TYPED_CHILDREN(OrganizationName);
                IMPL_CLONE_TYPED_CHILDREN(OrganizationDisplayName);
                IMPL_CLONE_TYPED_CHILDREN(OrganizationURL);
            }

            IMPL_XMLOBJECT_CLONE(Organization);
            IMPL_TYPED_CHILD(Extensions);
            IMPL_TYPED_CHILDREN(OrganizationName,m_pos_OrganizationDisplayName);
            IMPL_TYPED_CHILDREN(OrganizationDisplayName,m_pos_OrganizationURL);
            IMPL_TYPED_CHILDREN(OrganizationURL,m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Extensions,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(OrganizationName,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(OrganizationDisplayName,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(OrganizationURL,SAML20MD_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL ContactPersonImpl : public virtual ContactPerson,
            public AbstractComplexElement,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            list<XMLObject*>::iterator m_pos_TelephoneNumber;

            void init() {
                m_ContactType=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_Extensions=nullptr;
                m_Company=nullptr;
                m_GivenName=nullptr;
                m_SurName=nullptr;
                m_pos_Extensions=m_children.begin();
                m_pos_Company=m_pos_Extensions;
                ++m_pos_Company;
                m_pos_GivenName=m_pos_Company;
                ++m_pos_GivenName;
                m_pos_SurName=m_pos_GivenName;
                ++m_pos_SurName;
                m_pos_TelephoneNumber=m_pos_SurName;
                ++m_pos_TelephoneNumber;
            }

        public:
            virtual ~ContactPersonImpl() {
                XMLString::release(&m_ContactType);
            }

            ContactPersonImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            ContactPersonImpl(const ContactPersonImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src),
                        AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(ContactType);
                IMPL_CLONE_TYPED_CHILD(Extensions);
                IMPL_CLONE_TYPED_CHILD(Company);
                IMPL_CLONE_TYPED_CHILD(GivenName);
                IMPL_CLONE_TYPED_CHILD(SurName);
                IMPL_CLONE_TYPED_CHILDREN(EmailAddress);
                IMPL_CLONE_TYPED_CHILDREN(TelephoneNumber);
            }

            IMPL_XMLOBJECT_CLONE(ContactPerson);
            IMPL_STRING_ATTRIB(ContactType);
            IMPL_TYPED_CHILD(Extensions);
            IMPL_TYPED_CHILD(Company);
            IMPL_TYPED_CHILD(GivenName);
            IMPL_TYPED_CHILD(SurName);
            IMPL_TYPED_CHILDREN(EmailAddress,m_pos_TelephoneNumber);
            IMPL_TYPED_CHILDREN(TelephoneNumber,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),CONTACTTYPE_ATTRIB_NAME)) {
                        setContactType(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(ContactType,CONTACTTYPE,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Extensions,SAML20MD_NS,false);
                PROC_TYPED_CHILD(Company,SAML20MD_NS,false);
                PROC_TYPED_CHILD(GivenName,SAML20MD_NS,false);
                PROC_TYPED_CHILD(SurName,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(EmailAddress,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(TelephoneNumber,SAML20MD_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AdditionalMetadataLocationImpl : public virtual AdditionalMetadataLocation,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Namespace=nullptr;
            }

        public:
            virtual ~AdditionalMetadataLocationImpl() {
                XMLString::release(&m_Namespace);
            }

            AdditionalMetadataLocationImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AdditionalMetadataLocationImpl(const AdditionalMetadataLocationImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Namespace);
            }

            IMPL_XMLOBJECT_CLONE(AdditionalMetadataLocation);
            IMPL_STRING_ATTRIB(Namespace);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Namespace,NAMESPACE,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Namespace,NAMESPACE,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL KeyDescriptorImpl : public virtual KeyDescriptor,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
	        void init() {
                m_Use=nullptr;
                m_KeyInfo=nullptr;
                m_children.push_back(nullptr);
                m_pos_KeyInfo=m_children.begin();
    	    }

        public:
            virtual ~KeyDescriptorImpl() {
                XMLString::release(&m_Use);
            }

            KeyDescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            KeyDescriptorImpl(const KeyDescriptorImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Use);
                IMPL_CLONE_TYPED_CHILD(KeyInfo);
                IMPL_CLONE_TYPED_FOREIGN_CHILDREN(EncryptionMethod,xmlencryption);
            }

            IMPL_XMLOBJECT_CLONE(KeyDescriptor);
            IMPL_STRING_ATTRIB(Use);
            IMPL_TYPED_FOREIGN_CHILD(KeyInfo,xmlsignature);
            IMPL_TYPED_FOREIGN_CHILDREN(EncryptionMethod,xmlencryption,m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Use,USE,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(KeyInfo,xmlsignature,XMLSIG_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(EncryptionMethod,xmlencryption,SAML20MD_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Use,USE,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL EndpointTypeImpl : public virtual EndpointType,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Binding=m_Location=m_ResponseLocation=nullptr;
            }

        protected:
            EndpointTypeImpl() {
                init();
            }

        public:
            virtual ~EndpointTypeImpl() {
                XMLString::release(&m_Binding);
                XMLString::release(&m_Location);
                XMLString::release(&m_ResponseLocation);
            }

            EndpointTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            EndpointTypeImpl(const EndpointTypeImpl& src)
                    : AbstractXMLObject(src),
                        AbstractAttributeExtensibleXMLObject(src),
                        AbstractComplexElement(src),
                        AbstractDOMCachingXMLObject(src) {
                init();
            }

            void _clone(const EndpointTypeImpl& src) {
                IMPL_CLONE_ATTRIB(Binding);
                IMPL_CLONE_ATTRIB(Location);
                IMPL_CLONE_ATTRIB(ResponseLocation);
                IMPL_CLONE_XMLOBJECT_CHILDREN(UnknownXMLObject);
            }

            IMPL_XMLOBJECT_CLONE_EX(EndpointType);
            IMPL_STRING_ATTRIB(Binding);
            IMPL_STRING_ATTRIB(Location);
            IMPL_STRING_ATTRIB(ResponseLocation);
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),BINDING_ATTRIB_NAME)) {
                        setBinding(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),LOCATION_ATTRIB_NAME)) {
                        setLocation(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),RESPONSELOCATION_ATTRIB_NAME)) {
                        setResponseLocation(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Binding,BINDING,nullptr);
                MARSHALL_STRING_ATTRIB(Location,LOCATION,nullptr);
                MARSHALL_STRING_ATTRIB(ResponseLocation,RESPONSELOCATION,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAML20MD_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL IndexedEndpointTypeImpl : public virtual IndexedEndpointType, public EndpointTypeImpl
        {
            void init() {
                m_Index=nullptr;
                m_isDefault=XML_BOOL_NULL;
            }

        protected:
            IndexedEndpointTypeImpl() {
                init();
            }
        public:
            virtual ~IndexedEndpointTypeImpl() {
                XMLString::release(&m_Index);
            }

            IndexedEndpointTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            IndexedEndpointTypeImpl(const IndexedEndpointTypeImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {
                init();
            }

            void _clone(const IndexedEndpointTypeImpl& src) {
                EndpointTypeImpl::_clone(src);
                IMPL_CLONE_INTEGER_ATTRIB(Index);
                IMPL_CLONE_BOOLEAN_ATTRIB(isDefault);
            }

            IMPL_XMLOBJECT_CLONE_EX(IndexedEndpointType);
            IMPL_INTEGER_ATTRIB(Index);
            IMPL_BOOLEAN_ATTRIB(isDefault);

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),INDEX_ATTRIB_NAME)) {
                        setIndex(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),ISDEFAULT_ATTRIB_NAME)) {
                        setisDefault(value);
                        return;
                    }
                }
                EndpointTypeImpl::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_INTEGER_ATTRIB(Index,INDEX,nullptr);
                MARSHALL_BOOLEAN_ATTRIB(isDefault,ISDEFAULT,nullptr);
                EndpointTypeImpl::marshallAttributes(domElement);
            }
        };

        class SAML_DLLLOCAL ArtifactResolutionServiceImpl : public virtual ArtifactResolutionService, public IndexedEndpointTypeImpl
        {
        public:
            virtual ~ArtifactResolutionServiceImpl() {}

            ArtifactResolutionServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            ArtifactResolutionServiceImpl(const ArtifactResolutionServiceImpl& src) : AbstractXMLObject(src), IndexedEndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(ArtifactResolutionService);
        };

        class SAML_DLLLOCAL SingleLogoutServiceImpl : public virtual SingleLogoutService, public EndpointTypeImpl
        {
        public:
            virtual ~SingleLogoutServiceImpl() {}

            SingleLogoutServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            SingleLogoutServiceImpl(const SingleLogoutServiceImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(SingleLogoutService);
        };

        class SAML_DLLLOCAL ManageNameIDServiceImpl : public virtual ManageNameIDService, public EndpointTypeImpl
        {
        public:
            virtual ~ManageNameIDServiceImpl() {}

            ManageNameIDServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            ManageNameIDServiceImpl(const ManageNameIDServiceImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(ManageNameIDService);
        };

        class SAML_DLLLOCAL SingleSignOnServiceImpl : public virtual SingleSignOnService, public EndpointTypeImpl
        {
        public:
            virtual ~SingleSignOnServiceImpl() {}

            SingleSignOnServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            SingleSignOnServiceImpl(const SingleSignOnServiceImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(SingleSignOnService);
        };

        class SAML_DLLLOCAL NameIDMappingServiceImpl : public virtual NameIDMappingService, public EndpointTypeImpl
        {
        public:
            virtual ~NameIDMappingServiceImpl() {}

            NameIDMappingServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            NameIDMappingServiceImpl(const NameIDMappingServiceImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(NameIDMappingService);
        };

        class SAML_DLLLOCAL AssertionIDRequestServiceImpl : public virtual AssertionIDRequestService, public EndpointTypeImpl
        {
        public:
            virtual ~AssertionIDRequestServiceImpl() {}

            AssertionIDRequestServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AssertionIDRequestServiceImpl(const AssertionIDRequestServiceImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(AssertionIDRequestService);
        };

        class SAML_DLLLOCAL AssertionConsumerServiceImpl : public virtual AssertionConsumerService, public IndexedEndpointTypeImpl
        {
        public:
            virtual ~AssertionConsumerServiceImpl() {}

            AssertionConsumerServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AssertionConsumerServiceImpl(const AssertionConsumerServiceImpl& src) : AbstractXMLObject(src), IndexedEndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(AssertionConsumerService);
        };

        class SAML_DLLLOCAL AuthnQueryServiceImpl : public virtual AuthnQueryService, public EndpointTypeImpl
        {
        public:
            virtual ~AuthnQueryServiceImpl() {}

            AuthnQueryServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AuthnQueryServiceImpl(const AuthnQueryServiceImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(AuthnQueryService);
        };

        class SAML_DLLLOCAL AuthzServiceImpl : public virtual AuthzService, public EndpointTypeImpl
        {
        public:
            virtual ~AuthzServiceImpl() {}

            AuthzServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AuthzServiceImpl(const AuthzServiceImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(AuthzService);
        };

        class SAML_DLLLOCAL AttributeServiceImpl : public virtual AttributeService, public EndpointTypeImpl
        {
        public:
            virtual ~AttributeServiceImpl() {}

            AttributeServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AttributeServiceImpl(const AttributeServiceImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(AttributeService);
        };

        class SAML_DLLLOCAL RoleDescriptorImpl : public virtual RoleDescriptor,
            public virtual SignableObject,
            public AbstractComplexElement,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ID=m_ProtocolSupportEnumeration=m_ErrorURL=nullptr;
                m_ValidUntil=m_CacheDuration=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_Signature=nullptr;
                m_Extensions=nullptr;
                m_Organization=nullptr;
                m_pos_Signature=m_children.begin();
                m_pos_Extensions=m_pos_Signature;
                ++m_pos_Extensions;
                m_pos_Organization=m_pos_Extensions;
                ++m_pos_Organization;
                m_pos_ContactPerson=m_pos_Organization;
                ++m_pos_ContactPerson;
            }

        protected:
            list<XMLObject*>::iterator m_pos_ContactPerson;

            RoleDescriptorImpl() {
                init();
            }

        public:
            virtual ~RoleDescriptorImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_ProtocolSupportEnumeration);
                XMLString::release(&m_ErrorURL);
                delete m_ValidUntil;
                delete m_CacheDuration;
            }

            RoleDescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            RoleDescriptorImpl(const RoleDescriptorImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src),
                        AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
            }

            void _clone(const RoleDescriptorImpl& src) {
                IMPL_CLONE_ATTRIB(ID);
                IMPL_CLONE_ATTRIB(ProtocolSupportEnumeration);
                IMPL_CLONE_ATTRIB(ErrorURL);
                IMPL_CLONE_ATTRIB(ValidUntil);
                IMPL_CLONE_ATTRIB(CacheDuration);
                IMPL_CLONE_TYPED_CHILD(Signature);
                IMPL_CLONE_TYPED_CHILD(Extensions);
                IMPL_CLONE_TYPED_CHILD(Organization);
                IMPL_CLONE_TYPED_CHILDREN(KeyDescriptor);
                IMPL_CLONE_TYPED_CHILDREN(ContactPerson);
            }

            //IMPL_TYPED_CHILD(Signature);
            // Need customized setter.
        protected:
            xmlsignature::Signature* m_Signature;
            list<XMLObject*>::iterator m_pos_Signature;
        public:
            xmlsignature::Signature* getSignature() const {
                return m_Signature;
            }

            void setSignature(xmlsignature::Signature* sig) {
                prepareForAssignment(m_Signature,sig);
                *m_pos_Signature=m_Signature=sig;
                // Sync content reference back up.
                if (m_Signature)
                    m_Signature->setContentReference(new opensaml::ContentReference(*this));
            }

            RoleDescriptor* cloneRoleDescriptor() const {
                return dynamic_cast<RoleDescriptor*>(clone());
            }

            IMPL_ID_ATTRIB_EX(ID,ID,nullptr);
            IMPL_STRING_ATTRIB(ProtocolSupportEnumeration);
            IMPL_STRING_ATTRIB(ErrorURL);
            IMPL_DATETIME_ATTRIB(ValidUntil,SAMLTIME_MAX);
            IMPL_DURATION_ATTRIB(CacheDuration,0);
            IMPL_TYPED_CHILD(Extensions);
            IMPL_TYPED_CHILDREN(KeyDescriptor,m_pos_Organization);
            IMPL_TYPED_CHILD(Organization);
            IMPL_TYPED_CHILDREN(ContactPerson,m_pos_ContactPerson);

            bool hasSupport(const XMLCh* protocol) const {
                if (!protocol || !*protocol)
                    return true;
                if (m_ProtocolSupportEnumeration) {
                    // Look for first character.
                    XMLSize_t len=XMLString::stringLen(protocol);
                    XMLSize_t pos=0;
                    int index=XMLString::indexOf(m_ProtocolSupportEnumeration,protocol[0],pos);
                    while (index>=0) {
                        // Only possible match is if it's the first character or a space comes before it.
                        if (index==0 || m_ProtocolSupportEnumeration[index-1]==chSpace) {
                            // See if rest of protocol string is present.
                            if (0==XMLString::compareNString(m_ProtocolSupportEnumeration+index+1,protocol+1,len-1)) {
                                // Only possible match is if it's the last character or a space comes after it.
                                if (m_ProtocolSupportEnumeration[index+len]==chNull || m_ProtocolSupportEnumeration[index+len]==chSpace)
                                    return true;
                                else
                                    pos=index+len;
                            }
                            else {
                                // Move past last search and start again.
                                pos=index+1;
                            }
                        }
                        else {
                            // Move past last search and start again.
                            pos=index+1;
                        }
                        index=XMLString::indexOf(m_ProtocolSupportEnumeration,protocol[0],pos);
                    }
                }
                return false;
            }

            void addSupport(const XMLCh* protocol) {
                if (hasSupport(protocol))
                    return;
                if (m_ProtocolSupportEnumeration && *m_ProtocolSupportEnumeration) {
#ifdef HAVE_GOOD_STL
                    xstring pse(m_ProtocolSupportEnumeration);
                    pse = pse + chSpace + protocol;
                    setProtocolSupportEnumeration(pse.c_str());
#else
                    auto_ptr_char temp(m_ProtocolSupportEnumeration);
                    auto_ptr_char temp2(protocol);
                    string pse(temp.get());
                    pse = pse + ' ' + temp2.get();
                    auto_ptr_XMLCh temp3(pse.c_str());
                    setProtocolSupportEnumeration(temp3.get());
#endif
                }
                else {
                    setProtocolSupportEnumeration(protocol);
                }
            }

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),ID_ATTRIB_NAME)) {
                        setID(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),PROTOCOLSUPPORTENUMERATION_ATTRIB_NAME)) {
                        setProtocolSupportEnumeration(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),ERRORURL_ATTRIB_NAME)) {
                        setErrorURL(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),VALIDUNTIL_ATTRIB_NAME)) {
                        setValidUntil(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),CACHEDURATION_ATTRIB_NAME)) {
                        setCacheDuration(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void prepareForMarshalling() const {
                if (m_Signature)
                    declareNonVisibleNamespaces();
            }

            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_ID_ATTRIB(ID,ID,nullptr);
                MARSHALL_STRING_ATTRIB(ProtocolSupportEnumeration,PROTOCOLSUPPORTENUMERATION,nullptr);
                MARSHALL_STRING_ATTRIB(ErrorURL,ERRORURL,nullptr);
                MARSHALL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL,nullptr);
                MARSHALL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Signature,xmlsignature,XMLSIG_NS,false);
                PROC_TYPED_CHILD(Extensions,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(KeyDescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILD(Organization,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(ContactPerson,SAML20MD_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_ID_ATTRIB(ID,ID,nullptr);
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL RoleDescriptorTypeImpl : public virtual RoleDescriptorType, public RoleDescriptorImpl
        {
        public:
            virtual ~RoleDescriptorTypeImpl() {}

            RoleDescriptorTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            RoleDescriptorTypeImpl(const RoleDescriptorTypeImpl& src) : AbstractXMLObject(src), RoleDescriptorImpl(src) {
            }

            void _clone(const RoleDescriptorTypeImpl& src) {
                RoleDescriptorImpl::_clone(src);
                IMPL_CLONE_XMLOBJECT_CHILDREN(UnknownXMLObject);
            }

            IMPL_XMLOBJECT_CLONE_EX(RoleDescriptorType);
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                getUnknownXMLObjects().push_back(childXMLObject);
            }
        };

        class SAML_DLLLOCAL SSODescriptorTypeImpl : public virtual SSODescriptorType, public RoleDescriptorImpl
        {
            void init() {
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_ArtifactResolutionService=m_pos_ContactPerson;
                ++m_pos_ArtifactResolutionService;
                m_pos_SingleLogoutService=m_pos_ArtifactResolutionService;
                ++m_pos_SingleLogoutService;
                m_pos_ManageNameIDService=m_pos_SingleLogoutService;
                ++m_pos_ManageNameIDService;
                m_pos_NameIDFormat=m_pos_ManageNameIDService;
                ++m_pos_NameIDFormat;
            }

        protected:
            list<XMLObject*>::iterator m_pos_ArtifactResolutionService;
            list<XMLObject*>::iterator m_pos_SingleLogoutService;
            list<XMLObject*>::iterator m_pos_ManageNameIDService;
            list<XMLObject*>::iterator m_pos_NameIDFormat;

            SSODescriptorTypeImpl() {
                init();
            }

        public:
            virtual ~SSODescriptorTypeImpl() {}

            SSODescriptorTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SSODescriptorTypeImpl(const SSODescriptorTypeImpl& src) : AbstractXMLObject(src), RoleDescriptorImpl(src) {
                init();
            }

            void _clone(const SSODescriptorTypeImpl& src) {
                RoleDescriptorImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILDREN(ArtifactResolutionService);
                IMPL_CLONE_TYPED_CHILDREN(SingleLogoutService);
                IMPL_CLONE_TYPED_CHILDREN(ManageNameIDService);
                IMPL_CLONE_TYPED_CHILDREN(NameIDFormat);
            }

            SSODescriptorType* cloneSSODescriptorType() const {
                return dynamic_cast<SSODescriptorType*>(clone());
            }

            IMPL_TYPED_CHILDREN(ArtifactResolutionService,m_pos_ArtifactResolutionService);
            IMPL_TYPED_CHILDREN(SingleLogoutService,m_pos_SingleLogoutService);
            IMPL_TYPED_CHILDREN(ManageNameIDService,m_pos_ManageNameIDService);
            IMPL_TYPED_CHILDREN(NameIDFormat,m_pos_NameIDFormat);

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(ArtifactResolutionService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(SingleLogoutService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(ManageNameIDService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(NameIDFormat,SAML20MD_NS,false);
                RoleDescriptorImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL IDPSSODescriptorImpl : public virtual IDPSSODescriptor, public SSODescriptorTypeImpl
        {
            list<XMLObject*>::iterator m_pos_SingleSignOnService;
            list<XMLObject*>::iterator m_pos_NameIDMappingService;
            list<XMLObject*>::iterator m_pos_AssertionIDRequestService;
            list<XMLObject*>::iterator m_pos_AttributeProfile;

            void init() {
                m_WantAuthnRequestsSigned=XML_BOOL_NULL;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_SingleSignOnService=m_pos_NameIDFormat;
                ++m_pos_SingleSignOnService;
                m_pos_NameIDMappingService=m_pos_SingleSignOnService;
                ++m_pos_NameIDMappingService;
                m_pos_AssertionIDRequestService=m_pos_NameIDMappingService;
                ++m_pos_AssertionIDRequestService;
                m_pos_AttributeProfile=m_pos_AssertionIDRequestService;
                ++m_pos_AttributeProfile;
            }

        public:
            virtual ~IDPSSODescriptorImpl() {}

            IDPSSODescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            IDPSSODescriptorImpl(const IDPSSODescriptorImpl& src) : AbstractXMLObject(src), SSODescriptorTypeImpl(src) {
                init();
            }

            void _clone(const IDPSSODescriptorImpl& src) {
                SSODescriptorTypeImpl::_clone(src);
                IMPL_CLONE_BOOLEAN_ATTRIB(WantAuthnRequestsSigned);
                IMPL_CLONE_TYPED_CHILDREN(SingleSignOnService);
                IMPL_CLONE_TYPED_CHILDREN(NameIDMappingService);
                IMPL_CLONE_TYPED_CHILDREN(AssertionIDRequestService);
                IMPL_CLONE_TYPED_CHILDREN(AttributeProfile);
                IMPL_CLONE_TYPED_FOREIGN_CHILDREN(Attribute,saml2);
            }

            IMPL_XMLOBJECT_CLONE_EX(IDPSSODescriptor);
            IMPL_BOOLEAN_ATTRIB(WantAuthnRequestsSigned);
            IMPL_TYPED_CHILDREN(SingleSignOnService,m_pos_SingleSignOnService);
            IMPL_TYPED_CHILDREN(NameIDMappingService,m_pos_NameIDMappingService);
            IMPL_TYPED_CHILDREN(AssertionIDRequestService,m_pos_AssertionIDRequestService);
            IMPL_TYPED_CHILDREN(AttributeProfile,m_pos_AttributeProfile);
            IMPL_TYPED_FOREIGN_CHILDREN(Attribute,saml2,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),WANTAUTHNREQUESTSSIGNED_ATTRIB_NAME)) {
                        setWantAuthnRequestsSigned(value);
                        return;
                    }
                }
                RoleDescriptorImpl::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_BOOLEAN_ATTRIB(WantAuthnRequestsSigned,WANTAUTHNREQUESTSSIGNED,nullptr);
                RoleDescriptorImpl::marshallAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(SingleSignOnService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(NameIDMappingService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AssertionIDRequestService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AttributeProfile,SAML20MD_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(Attribute,saml2,SAML20_NS,false);
                SSODescriptorTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL RequestedAttributeImpl : public virtual RequestedAttribute,
            public AbstractComplexElement,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Name=m_NameFormat=m_FriendlyName=nullptr;
                m_isRequired=XML_BOOL_NULL;
            }

        public:
            virtual ~RequestedAttributeImpl() {
                XMLString::release(&m_Name);
                XMLString::release(&m_NameFormat);
                XMLString::release(&m_FriendlyName);
            }

            RequestedAttributeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            RequestedAttributeImpl(const RequestedAttributeImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src),
                        AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Name);
                IMPL_CLONE_ATTRIB(NameFormat);
                IMPL_CLONE_ATTRIB(FriendlyName);
                IMPL_CLONE_BOOLEAN_ATTRIB(isRequired);
                IMPL_CLONE_XMLOBJECT_CHILDREN(AttributeValue);
            }

            IMPL_XMLOBJECT_CLONE2(RequestedAttribute,Attribute);
            IMPL_STRING_ATTRIB(Name);
            IMPL_STRING_ATTRIB(NameFormat);
            IMPL_STRING_ATTRIB(FriendlyName);
            IMPL_BOOLEAN_ATTRIB(isRequired);
            IMPL_XMLOBJECT_CHILDREN(AttributeValue,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),NAME_ATTRIB_NAME)) {
                        setName(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),NAMEFORMAT_ATTRIB_NAME)) {
                        setNameFormat(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),FRIENDLYNAME_ATTRIB_NAME)) {
                        setFriendlyName(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),ISREQUIRED_ATTRIB_NAME)) {
                        setisRequired(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Name,NAME,nullptr);
                MARSHALL_STRING_ATTRIB(NameFormat,NAMEFORMAT,nullptr);
                MARSHALL_STRING_ATTRIB(FriendlyName,FRIENDLYNAME,nullptr);
                MARSHALL_BOOLEAN_ATTRIB(isRequired,ISREQUIRED,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                getAttributeValues().push_back(childXMLObject);
            }

            void processAttribute(const DOMAttr* attribute) {
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AttributeConsumingServiceImpl : public virtual AttributeConsumingService,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            list<XMLObject*>::iterator m_pos_ServiceDescription;
            list<XMLObject*>::iterator m_pos_RequestedAttribute;

	        void init() {
                m_Index=nullptr;
                m_isDefault=XML_BOOL_NULL;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_ServiceDescription=m_children.begin();
                m_pos_RequestedAttribute=m_pos_ServiceDescription;
                ++m_pos_RequestedAttribute;
            }

        public:
            virtual ~AttributeConsumingServiceImpl() {
                XMLString::release(&m_Index);
            }

            AttributeConsumingServiceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AttributeConsumingServiceImpl(const AttributeConsumingServiceImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_INTEGER_ATTRIB(Index);
                IMPL_CLONE_BOOLEAN_ATTRIB(isDefault);
                IMPL_CLONE_TYPED_CHILDREN(ServiceName);
                IMPL_CLONE_TYPED_CHILDREN(ServiceDescription);
                IMPL_CLONE_TYPED_CHILDREN(RequestedAttribute);
            }

            IMPL_XMLOBJECT_CLONE(AttributeConsumingService);
            IMPL_INTEGER_ATTRIB(Index);
            IMPL_BOOLEAN_ATTRIB(isDefault);
            IMPL_TYPED_CHILDREN(ServiceName,m_pos_ServiceDescription);
            IMPL_TYPED_CHILDREN(ServiceDescription,m_pos_RequestedAttribute);
            IMPL_TYPED_CHILDREN(RequestedAttribute,m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_INTEGER_ATTRIB(Index,INDEX,nullptr);
                MARSHALL_BOOLEAN_ATTRIB(isDefault,ISDEFAULT,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(ServiceName,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(ServiceDescription,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(RequestedAttribute,SAML20MD_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_INTEGER_ATTRIB(Index,INDEX,nullptr);
                PROC_BOOLEAN_ATTRIB(isDefault,ISDEFAULT,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL SPSSODescriptorImpl : public virtual SPSSODescriptor, public SSODescriptorTypeImpl
        {
            list<XMLObject*>::iterator m_pos_AssertionConsumerService;

            void init() {
                m_AuthnRequestsSigned=XML_BOOL_NULL;
                m_WantAssertionsSigned=XML_BOOL_NULL;
                m_children.push_back(nullptr);
                m_pos_AssertionConsumerService=m_pos_NameIDFormat;
                ++m_pos_AssertionConsumerService;
            }

        public:
            virtual ~SPSSODescriptorImpl() {}

            SPSSODescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SPSSODescriptorImpl(const SPSSODescriptorImpl& src) : AbstractXMLObject(src), SSODescriptorTypeImpl(src) {
                init();
            }

            void _clone(const SPSSODescriptorImpl& src) {
                SSODescriptorTypeImpl::_clone(src);
                IMPL_CLONE_BOOLEAN_ATTRIB(AuthnRequestsSigned);
                IMPL_CLONE_BOOLEAN_ATTRIB(WantAssertionsSigned);
                IMPL_CLONE_TYPED_CHILDREN(AssertionConsumerService);
                IMPL_CLONE_TYPED_CHILDREN(AttributeConsumingService);
            }

            IMPL_XMLOBJECT_CLONE_EX(SPSSODescriptor);
            IMPL_BOOLEAN_ATTRIB(AuthnRequestsSigned);
            IMPL_BOOLEAN_ATTRIB(WantAssertionsSigned);
            IMPL_TYPED_CHILDREN(AssertionConsumerService,m_pos_AssertionConsumerService);
            IMPL_TYPED_CHILDREN(AttributeConsumingService,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),AUTHNREQUESTSSIGNED_ATTRIB_NAME)) {
                        setAuthnRequestsSigned(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),WANTASSERTIONSSIGNED_ATTRIB_NAME)) {
                        setWantAssertionsSigned(value);
                        return;
                    }
                }
                RoleDescriptorImpl::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_BOOLEAN_ATTRIB(AuthnRequestsSigned,AUTHNREQUESTSSIGNED,nullptr);
                MARSHALL_BOOLEAN_ATTRIB(WantAssertionsSigned,WANTASSERTIONSSIGNED,nullptr);
                RoleDescriptorImpl::marshallAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AssertionConsumerService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AttributeConsumingService,SAML20MD_NS,false);
                SSODescriptorTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthnAuthorityDescriptorImpl : public virtual AuthnAuthorityDescriptor, public RoleDescriptorImpl
        {
            list<XMLObject*>::iterator m_pos_AuthnQueryService;
            list<XMLObject*>::iterator m_pos_AssertionIDRequestService;

            void init() {
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_AuthnQueryService=m_pos_ContactPerson;
                ++m_pos_AuthnQueryService;
                m_pos_AssertionIDRequestService=m_pos_AuthnQueryService;
                ++m_pos_AssertionIDRequestService;
            }

        public:
            virtual ~AuthnAuthorityDescriptorImpl() {}

            AuthnAuthorityDescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AuthnAuthorityDescriptorImpl(const AuthnAuthorityDescriptorImpl& src) : AbstractXMLObject(src), RoleDescriptorImpl(src) {
                init();
            }

            void _clone(const AuthnAuthorityDescriptorImpl& src) {
                RoleDescriptorImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILDREN(AuthnQueryService);
                IMPL_CLONE_TYPED_CHILDREN(AssertionIDRequestService);
                IMPL_CLONE_TYPED_CHILDREN(NameIDFormat);
            }

            IMPL_XMLOBJECT_CLONE_EX(AuthnAuthorityDescriptor);
            IMPL_TYPED_CHILDREN(AuthnQueryService,m_pos_AuthnQueryService);
            IMPL_TYPED_CHILDREN(AssertionIDRequestService,m_pos_AssertionIDRequestService);
            IMPL_TYPED_CHILDREN(NameIDFormat,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AuthnQueryService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AssertionIDRequestService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(NameIDFormat,SAML20MD_NS,false);
                RoleDescriptorImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL PDPDescriptorImpl : public virtual PDPDescriptor, public RoleDescriptorImpl
        {
            list<XMLObject*>::iterator m_pos_AuthzService;
            list<XMLObject*>::iterator m_pos_AssertionIDRequestService;

            void init() {
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_AuthzService=m_pos_ContactPerson;
                ++m_pos_AuthzService;
                m_pos_AssertionIDRequestService=m_pos_AuthzService;
                ++m_pos_AssertionIDRequestService;
            }

        public:
            virtual ~PDPDescriptorImpl() {}

            PDPDescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            PDPDescriptorImpl(const PDPDescriptorImpl& src) : AbstractXMLObject(src), RoleDescriptorImpl(src) {
                init();
            }

            void _clone(const PDPDescriptorImpl& src) {
                RoleDescriptorImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILDREN(AuthzService);
                IMPL_CLONE_TYPED_CHILDREN(AssertionIDRequestService);
                IMPL_CLONE_TYPED_CHILDREN(NameIDFormat);
            }

            IMPL_XMLOBJECT_CLONE_EX(PDPDescriptor);
            IMPL_TYPED_CHILDREN(AuthzService,m_pos_AuthzService);
            IMPL_TYPED_CHILDREN(AssertionIDRequestService,m_pos_AssertionIDRequestService);
            IMPL_TYPED_CHILDREN(NameIDFormat,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AuthzService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AssertionIDRequestService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(NameIDFormat,SAML20MD_NS,false);
                RoleDescriptorImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AttributeAuthorityDescriptorImpl : public virtual AttributeAuthorityDescriptor, public RoleDescriptorImpl
        {
            list<XMLObject*>::iterator m_pos_AttributeService;
            list<XMLObject*>::iterator m_pos_AssertionIDRequestService;
            list<XMLObject*>::iterator m_pos_NameIDFormat;
            list<XMLObject*>::iterator m_pos_AttributeProfile;

            void init() {
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_AttributeService=m_pos_ContactPerson;
                ++m_pos_AttributeService;
                m_pos_AssertionIDRequestService=m_pos_AttributeService;
                ++m_pos_AssertionIDRequestService;
                m_pos_NameIDFormat=m_pos_AssertionIDRequestService;
                ++m_pos_NameIDFormat;
                m_pos_AttributeProfile=m_pos_NameIDFormat;
                ++m_pos_AttributeProfile;
            }

        public:
            virtual ~AttributeAuthorityDescriptorImpl() {}

            AttributeAuthorityDescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AttributeAuthorityDescriptorImpl(const AttributeAuthorityDescriptorImpl& src) : AbstractXMLObject(src), RoleDescriptorImpl(src) {
                init();
            }

            void _clone(const AttributeAuthorityDescriptorImpl& src) {
                RoleDescriptorImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILDREN(AttributeService);
                IMPL_CLONE_TYPED_CHILDREN(AssertionIDRequestService);
                IMPL_CLONE_TYPED_CHILDREN(NameIDFormat);
                IMPL_CLONE_TYPED_CHILDREN(AttributeProfile);
                IMPL_CLONE_TYPED_FOREIGN_CHILDREN(Attribute,saml2);
            }

            IMPL_XMLOBJECT_CLONE_EX(AttributeAuthorityDescriptor);
            IMPL_TYPED_CHILDREN(AttributeService,m_pos_AttributeService);
            IMPL_TYPED_CHILDREN(AssertionIDRequestService,m_pos_AssertionIDRequestService);
            IMPL_TYPED_CHILDREN(NameIDFormat,m_pos_NameIDFormat);
            IMPL_TYPED_CHILDREN(AttributeProfile,m_pos_AttributeProfile);
            IMPL_TYPED_FOREIGN_CHILDREN(Attribute,saml2,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AttributeService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AssertionIDRequestService,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(NameIDFormat,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AttributeProfile,SAML20MD_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(Attribute,saml2,SAML20_NS,false);
                RoleDescriptorImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL QueryDescriptorTypeImpl : public virtual QueryDescriptorType, public RoleDescriptorImpl
        {
            void init() {
                m_WantAssertionsSigned=XML_BOOL_NULL;
                m_children.push_back(nullptr);
                m_pos_NameIDFormat=m_pos_ContactPerson;
                ++m_pos_NameIDFormat;
            }

        protected:
            list<XMLObject*>::iterator m_pos_NameIDFormat;

            QueryDescriptorTypeImpl() {
                init();
            }

        public:
            virtual ~QueryDescriptorTypeImpl() {}

            QueryDescriptorTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            QueryDescriptorTypeImpl(const QueryDescriptorTypeImpl& src) : AbstractXMLObject(src), RoleDescriptorImpl(src) {
                init();
            }

            void _clone(const QueryDescriptorTypeImpl& src) {
                RoleDescriptorImpl::_clone(src);
                IMPL_CLONE_BOOLEAN_ATTRIB(WantAssertionsSigned);
                IMPL_CLONE_TYPED_CHILDREN(NameIDFormat);
            }

            QueryDescriptorType* cloneQueryDescriptorType() const {
                return dynamic_cast<QueryDescriptorType*>(clone());
            }

            IMPL_BOOLEAN_ATTRIB(WantAssertionsSigned);
            IMPL_TYPED_CHILDREN(NameIDFormat,m_pos_NameIDFormat);

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),WANTASSERTIONSSIGNED_ATTRIB_NAME)) {
                        setWantAssertionsSigned(value);
                        return;
                    }
                }
                RoleDescriptorImpl::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_BOOLEAN_ATTRIB(WantAssertionsSigned,WANTASSERTIONSSIGNED,nullptr);
                RoleDescriptorImpl::marshallAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(NameIDFormat,SAML20MD_NS,false);
                RoleDescriptorImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthnQueryDescriptorTypeImpl : public virtual AuthnQueryDescriptorType, public QueryDescriptorTypeImpl
        {
        public:
            virtual ~AuthnQueryDescriptorTypeImpl() {}

            AuthnQueryDescriptorTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AuthnQueryDescriptorTypeImpl(const AuthnQueryDescriptorTypeImpl& src) : AbstractXMLObject(src), QueryDescriptorTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(AuthnQueryDescriptorType);
        };

        class SAML_DLLLOCAL AttributeQueryDescriptorTypeImpl : public virtual AttributeQueryDescriptorType, public QueryDescriptorTypeImpl
        {
        public:
            virtual ~AttributeQueryDescriptorTypeImpl() {}

            AttributeQueryDescriptorTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AttributeQueryDescriptorTypeImpl(const AttributeQueryDescriptorTypeImpl& src) : AbstractXMLObject(src), QueryDescriptorTypeImpl(src) {
            }

            void _clone(const AttributeQueryDescriptorTypeImpl& src) {
                QueryDescriptorTypeImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILDREN(AttributeConsumingService);
            }

            IMPL_XMLOBJECT_CLONE_EX(AttributeQueryDescriptorType);
            IMPL_TYPED_CHILDREN(AttributeConsumingService,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AttributeConsumingService,SAML20MD_NS,false);
                QueryDescriptorTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthzDecisionQueryDescriptorTypeImpl : public virtual AuthzDecisionQueryDescriptorType, public QueryDescriptorTypeImpl
        {
        public:
            virtual ~AuthzDecisionQueryDescriptorTypeImpl() {}

            AuthzDecisionQueryDescriptorTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AuthzDecisionQueryDescriptorTypeImpl(const AuthzDecisionQueryDescriptorTypeImpl& src) : AbstractXMLObject(src), QueryDescriptorTypeImpl(src) {
            }

            void _clone(const AuthzDecisionQueryDescriptorTypeImpl& src) {
                QueryDescriptorTypeImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILDREN(ActionNamespace);
            }

            IMPL_XMLOBJECT_CLONE_EX(AuthzDecisionQueryDescriptorType);
            IMPL_TYPED_CHILDREN(ActionNamespace,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(ActionNamespace,samlconstants::SAML20MD_QUERY_EXT_NS,false);
                QueryDescriptorTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AffiliationDescriptorImpl : public virtual AffiliationDescriptor,
            public virtual SignableObject,
            public AbstractComplexElement,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            list<XMLObject*>::iterator m_pos_AffiliateMember;

            void init() {
                m_ID=m_AffiliationOwnerID=nullptr;
                m_ValidUntil=m_CacheDuration=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_Signature=nullptr;
                m_Extensions=nullptr;
                m_pos_Signature=m_children.begin();
                m_pos_Extensions=m_pos_Signature;
                ++m_pos_Extensions;
                m_pos_AffiliateMember=m_pos_Extensions;
                ++m_pos_AffiliateMember;
            }

        public:
            virtual ~AffiliationDescriptorImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_AffiliationOwnerID);
                delete m_ValidUntil;
                delete m_CacheDuration;
            }

            AffiliationDescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AffiliationDescriptorImpl(const AffiliationDescriptorImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src),
                        AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(ID);
                IMPL_CLONE_ATTRIB(AffiliationOwnerID);
                IMPL_CLONE_ATTRIB(ValidUntil);
                IMPL_CLONE_ATTRIB(CacheDuration);
                IMPL_CLONE_TYPED_CHILD(Signature);
                IMPL_CLONE_TYPED_CHILD(Extensions);
                IMPL_CLONE_TYPED_CHILDREN(KeyDescriptor);
                IMPL_CLONE_TYPED_CHILDREN(AffiliateMember);
            }

            IMPL_XMLOBJECT_CLONE(AffiliationDescriptor);

            //IMPL_TYPED_CHILD(Signature);
            // Need customized setter.
        protected:
            xmlsignature::Signature* m_Signature;
            list<XMLObject*>::iterator m_pos_Signature;
        public:
            xmlsignature::Signature* getSignature() const {
                return m_Signature;
            }

            void setSignature(xmlsignature::Signature* sig) {
                prepareForAssignment(m_Signature,sig);
                *m_pos_Signature=m_Signature=sig;
                // Sync content reference back up.
                if (m_Signature)
                    m_Signature->setContentReference(new opensaml::ContentReference(*this));
            }

            IMPL_ID_ATTRIB_EX(ID,ID,nullptr);
            IMPL_STRING_ATTRIB(AffiliationOwnerID);
            IMPL_DATETIME_ATTRIB(ValidUntil,SAMLTIME_MAX);
            IMPL_DURATION_ATTRIB(CacheDuration,0);
            IMPL_TYPED_CHILD(Extensions);
            IMPL_TYPED_CHILDREN(AffiliateMember,m_pos_AffiliateMember);
            IMPL_TYPED_CHILDREN(KeyDescriptor,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),ID_ATTRIB_NAME)) {
                        setID(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),AFFILIATIONOWNERID_ATTRIB_NAME)) {
                        setAffiliationOwnerID(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),VALIDUNTIL_ATTRIB_NAME)) {
                        setValidUntil(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),CACHEDURATION_ATTRIB_NAME)) {
                        setCacheDuration(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void prepareForMarshalling() const {
                if (m_Signature)
                    declareNonVisibleNamespaces();
            }

            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_ID_ATTRIB(ID,ID,nullptr);
                MARSHALL_STRING_ATTRIB(AffiliationOwnerID,AFFILIATIONOWNERID,nullptr);
                MARSHALL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL,nullptr);
                MARSHALL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Signature,xmlsignature,XMLSIG_NS,false);
                PROC_TYPED_CHILD(Extensions,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AffiliateMember,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(KeyDescriptor,SAML20MD_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_ID_ATTRIB(ID,ID,nullptr);
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL EntityDescriptorImpl : public virtual EntityDescriptor,
            public virtual SignableObject,
            public AbstractComplexElement,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            list<XMLObject*>::iterator m_pos_ContactPerson;

            void init() {
                m_ID=m_EntityID=nullptr;
                m_ValidUntil=m_CacheDuration=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_Signature=nullptr;
                m_Extensions=nullptr;
                m_AffiliationDescriptor=nullptr;
                m_Organization=nullptr;
                m_pos_Signature=m_children.begin();
                m_pos_Extensions=m_pos_Signature;
                ++m_pos_Extensions;
                m_pos_AffiliationDescriptor=m_pos_Extensions;
                ++m_pos_AffiliationDescriptor;
                m_pos_Organization=m_pos_AffiliationDescriptor;
                ++m_pos_Organization;
                m_pos_ContactPerson=m_pos_Organization;
                ++m_pos_ContactPerson;
            }

        public:
            virtual ~EntityDescriptorImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_EntityID);
                delete m_ValidUntil;
                delete m_CacheDuration;
            }

            EntityDescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            EntityDescriptorImpl(const EntityDescriptorImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src),
                        AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(ID);
                IMPL_CLONE_ATTRIB(EntityID);
                IMPL_CLONE_ATTRIB(ValidUntil);
                IMPL_CLONE_ATTRIB(CacheDuration);
                IMPL_CLONE_TYPED_CHILD(Signature);
                IMPL_CLONE_TYPED_CHILD(Extensions);
                IMPL_CLONE_TYPED_CHILD(AffiliationDescriptor);
                IMPL_CLONE_TYPED_CHILD(Organization);

                IMPL_CLONE_CHILDBAG_BEGIN;
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(IDPSSODescriptor);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(SPSSODescriptor);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(AuthnAuthorityDescriptor);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(AttributeAuthorityDescriptor);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(PDPDescriptor);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(AuthnQueryDescriptorType);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(AttributeQueryDescriptorType);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(AuthzDecisionQueryDescriptorType);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(RoleDescriptor);
                IMPL_CLONE_CHILDBAG_END;

                IMPL_CLONE_TYPED_CHILDREN(ContactPerson);
                IMPL_CLONE_TYPED_CHILDREN(AdditionalMetadataLocation);
            }

            IMPL_XMLOBJECT_CLONE(EntityDescriptor);

            //IMPL_TYPED_CHILD(Signature);
            // Need customized setter.
        protected:
            xmlsignature::Signature* m_Signature;
            list<XMLObject*>::iterator m_pos_Signature;
        public:
            xmlsignature::Signature* getSignature() const {
                return m_Signature;
            }

            void setSignature(xmlsignature::Signature* sig) {
                prepareForAssignment(m_Signature,sig);
                *m_pos_Signature=m_Signature=sig;
                // Sync content reference back up.
                if (m_Signature)
                    m_Signature->setContentReference(new opensaml::ContentReference(*this));
            }

            IMPL_ID_ATTRIB_EX(ID,ID,nullptr);
            IMPL_STRING_ATTRIB(EntityID);
            IMPL_DATETIME_ATTRIB(ValidUntil,SAMLTIME_MAX);
            IMPL_DURATION_ATTRIB(CacheDuration,0);
            IMPL_TYPED_CHILD(Extensions);
            IMPL_TYPED_CHILDREN(RoleDescriptor,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILDREN(IDPSSODescriptor,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILDREN(SPSSODescriptor,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILDREN(AuthnAuthorityDescriptor,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILDREN(AttributeAuthorityDescriptor,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILDREN(PDPDescriptor,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILDREN(AuthnQueryDescriptorType,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILDREN(AttributeQueryDescriptorType,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILDREN(AuthzDecisionQueryDescriptorType,m_pos_AffiliationDescriptor);
            IMPL_TYPED_CHILD(AffiliationDescriptor);
            IMPL_TYPED_CHILD(Organization);
            IMPL_TYPED_CHILDREN(ContactPerson,m_pos_ContactPerson);
            IMPL_TYPED_CHILDREN(AdditionalMetadataLocation,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),ID_ATTRIB_NAME)) {
                        setID(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),ENTITYID_ATTRIB_NAME)) {
                        setEntityID(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),VALIDUNTIL_ATTRIB_NAME)) {
                        setValidUntil(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),CACHEDURATION_ATTRIB_NAME)) {
                        setCacheDuration(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }

            const RoleDescriptor* getRoleDescriptor(const xmltooling::QName& qname, const XMLCh* protocol) const {
                // Check for "known" elements/types.
                if (qname == IDPSSODescriptor::ELEMENT_QNAME)
                    return find_if(m_IDPSSODescriptors, isValidForProtocol(protocol));
                if (qname == SPSSODescriptor::ELEMENT_QNAME)
                    return find_if(m_SPSSODescriptors, isValidForProtocol(protocol));
                if (qname == AuthnAuthorityDescriptor::ELEMENT_QNAME)
                    return find_if(m_AuthnAuthorityDescriptors, isValidForProtocol(protocol));
                if (qname == AttributeAuthorityDescriptor::ELEMENT_QNAME)
                    return find_if(m_AttributeAuthorityDescriptors, isValidForProtocol(protocol));
                if (qname == PDPDescriptor::ELEMENT_QNAME)
                    return find_if(m_PDPDescriptors, isValidForProtocol(protocol));
                if (qname == AuthnQueryDescriptorType::TYPE_QNAME)
                    return find_if(m_AuthnQueryDescriptorTypes, isValidForProtocol(protocol));
                if (qname == AttributeQueryDescriptorType::TYPE_QNAME)
                    return find_if(m_AttributeQueryDescriptorTypes, isValidForProtocol(protocol));
                if (qname == AuthzDecisionQueryDescriptorType::TYPE_QNAME)
                    return find_if(m_AuthzDecisionQueryDescriptorTypes, isValidForProtocol(protocol));

                vector<RoleDescriptor*>::const_iterator i =
                    find_if(m_RoleDescriptors.begin(), m_RoleDescriptors.end(), ofTypeValidForProtocol(qname,protocol));
                return (i!=m_RoleDescriptors.end()) ? *i : nullptr;
            }

        protected:
            void prepareForMarshalling() const {
                if (m_Signature)
                    declareNonVisibleNamespaces();
            }

            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_ID_ATTRIB(ID,ID,nullptr);
                MARSHALL_STRING_ATTRIB(EntityID,ENTITYID,nullptr);
                MARSHALL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL,nullptr);
                MARSHALL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Signature,xmlsignature,XMLSIG_NS,false);
                PROC_TYPED_CHILD(Extensions,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(IDPSSODescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(SPSSODescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AuthnAuthorityDescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AttributeAuthorityDescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(PDPDescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AuthnQueryDescriptorType,samlconstants::SAML20MD_QUERY_EXT_NS,false);
                PROC_TYPED_CHILDREN(AttributeQueryDescriptorType,samlconstants::SAML20MD_QUERY_EXT_NS,false);
                PROC_TYPED_CHILDREN(AuthzDecisionQueryDescriptorType,samlconstants::SAML20MD_QUERY_EXT_NS,false);
                PROC_TYPED_CHILDREN(RoleDescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILD(AffiliationDescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILD(Organization,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(ContactPerson,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(AdditionalMetadataLocation,SAML20MD_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_ID_ATTRIB(ID,ID,nullptr);
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL EntitiesDescriptorImpl : public virtual EntitiesDescriptor,
            public virtual SignableObject,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ID=m_Name=nullptr;
                m_ValidUntil=m_CacheDuration=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_Signature=nullptr;
                m_Extensions=nullptr;
                m_pos_Signature=m_children.begin();
                m_pos_Extensions=m_pos_Signature;
                ++m_pos_Extensions;
            }

        public:
            virtual ~EntitiesDescriptorImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_Name);
                delete m_ValidUntil;
                delete m_CacheDuration;
            }

            EntitiesDescriptorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            EntitiesDescriptorImpl(const EntitiesDescriptorImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(ID);
                IMPL_CLONE_ATTRIB(Name);
                IMPL_CLONE_ATTRIB(ValidUntil);
                IMPL_CLONE_ATTRIB(CacheDuration);
                IMPL_CLONE_TYPED_CHILD(Signature);
                IMPL_CLONE_TYPED_CHILD(Extensions);

                IMPL_CLONE_CHILDBAG_BEGIN;
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(EntityDescriptor);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(EntitiesDescriptor);
                IMPL_CLONE_CHILDBAG_END;
            }

            IMPL_XMLOBJECT_CLONE(EntitiesDescriptor);

            //IMPL_TYPED_CHILD(Signature);
            // Need customized setter.
        protected:
            xmlsignature::Signature* m_Signature;
            list<XMLObject*>::iterator m_pos_Signature;
        public:
            xmlsignature::Signature* getSignature() const {
                return m_Signature;
            }

            void setSignature(xmlsignature::Signature* sig) {
                prepareForAssignment(m_Signature,sig);
                *m_pos_Signature=m_Signature=sig;
                // Sync content reference back up.
                if (m_Signature)
                    m_Signature->setContentReference(new opensaml::ContentReference(*this));
            }

            IMPL_ID_ATTRIB_EX(ID,ID,nullptr);
            IMPL_STRING_ATTRIB(Name);
            IMPL_DATETIME_ATTRIB(ValidUntil,SAMLTIME_MAX);
            IMPL_DURATION_ATTRIB(CacheDuration,0);
            IMPL_TYPED_CHILD(Extensions);
            IMPL_TYPED_CHILDREN(EntityDescriptor,m_children.end());
            IMPL_TYPED_CHILDREN(EntitiesDescriptor,m_children.end());

        protected:
            void prepareForMarshalling() const {
                if (m_Signature)
                    declareNonVisibleNamespaces();
            }

            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_ID_ATTRIB(ID,ID,nullptr);
                MARSHALL_STRING_ATTRIB(Name,NAME,nullptr);
                MARSHALL_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL,nullptr);
                MARSHALL_DATETIME_ATTRIB(CacheDuration,CACHEDURATION,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Signature,xmlsignature,XMLSIG_NS,false);
                PROC_TYPED_CHILD(Extensions,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(EntityDescriptor,SAML20MD_NS,false);
                PROC_TYPED_CHILDREN(EntitiesDescriptor,SAML20MD_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_ID_ATTRIB(ID,ID,nullptr);
                PROC_STRING_ATTRIB(Name,NAME,nullptr);
                PROC_DATETIME_ATTRIB(ValidUntil,VALIDUNTIL,nullptr);
                PROC_DATETIME_ATTRIB(CacheDuration,CACHEDURATION,nullptr);
            }
        };

        class SAML_DLLLOCAL DiscoveryResponseImpl : public virtual DiscoveryResponse, public IndexedEndpointTypeImpl
        {
        public:
            virtual ~DiscoveryResponseImpl() {}

            DiscoveryResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            DiscoveryResponseImpl(const DiscoveryResponseImpl& src) : AbstractXMLObject(src), IndexedEndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(DiscoveryResponse);
        };

        class SAML_DLLLOCAL RequestInitiatorImpl : public virtual RequestInitiator, public EndpointTypeImpl
        {
        public:
            virtual ~RequestInitiatorImpl() {}

            RequestInitiatorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            RequestInitiatorImpl(const RequestInitiatorImpl& src) : AbstractXMLObject(src), EndpointTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(RequestInitiator);
        };

        class SAML_DLLLOCAL EntityAttributesImpl : public virtual EntityAttributes,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~EntityAttributesImpl() {}

            EntityAttributesImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            EntityAttributesImpl(const EntityAttributesImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                IMPL_CLONE_CHILDBAG_BEGIN;
                    IMPL_CLONE_TYPED_FOREIGN_CHILD_IN_BAG(Attribute,saml2);
                    IMPL_CLONE_TYPED_FOREIGN_CHILD_IN_BAG(Assertion,saml2);
                IMPL_CLONE_CHILDBAG_END;
            }

            IMPL_XMLOBJECT_CLONE(EntityAttributes);
            IMPL_TYPED_FOREIGN_CHILDREN(Attribute,saml2,m_children.end());
            IMPL_TYPED_FOREIGN_CHILDREN(Assertion,saml2,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(Attribute,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(Assertion,saml2,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL DigestMethodImpl : public virtual DigestMethod,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~DigestMethodImpl() {
                XMLString::release(&m_Algorithm);
            }

            DigestMethodImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType), m_Algorithm(nullptr) {
            }

            DigestMethodImpl(const DigestMethodImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src), m_Algorithm(nullptr) {
                IMPL_CLONE_ATTRIB(Algorithm);
                IMPL_CLONE_XMLOBJECT_CHILDREN(UnknownXMLObject);
            }

            IMPL_XMLOBJECT_CLONE(DigestMethod);
            IMPL_STRING_ATTRIB(Algorithm);
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Algorithm,ALGORITHM,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                // Unknown child.
                getUnknownXMLObjects().push_back(childXMLObject);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Algorithm,ALGORITHM,nullptr);
            }
        };

        class SAML_DLLLOCAL SigningMethodImpl : public virtual SigningMethod,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Algorithm = m_MinKeySize = m_MaxKeySize = nullptr;
            }

        public:
            virtual ~SigningMethodImpl() {
                XMLString::release(&m_Algorithm);
                XMLString::release(&m_MinKeySize);
                XMLString::release(&m_MaxKeySize);
            }

            SigningMethodImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SigningMethodImpl(const SigningMethodImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Algorithm);
                IMPL_CLONE_INTEGER_ATTRIB(MinKeySize);
                IMPL_CLONE_INTEGER_ATTRIB(MaxKeySize);
                IMPL_CLONE_XMLOBJECT_CHILDREN(UnknownXMLObject);
            }

            IMPL_XMLOBJECT_CLONE(SigningMethod);
            IMPL_STRING_ATTRIB(Algorithm);
            IMPL_INTEGER_ATTRIB(MinKeySize);
            IMPL_INTEGER_ATTRIB(MaxKeySize);
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Algorithm,ALGORITHM,nullptr);
                MARSHALL_INTEGER_ATTRIB(MinKeySize,MINKEYSIZE,nullptr);
                MARSHALL_INTEGER_ATTRIB(MaxKeySize,MAXKEYSIZE,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                // Unknown child.
                getUnknownXMLObjects().push_back(childXMLObject);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Algorithm,ALGORITHM,nullptr);
                PROC_INTEGER_ATTRIB(MinKeySize,MINKEYSIZE,nullptr);
                PROC_INTEGER_ATTRIB(MaxKeySize,MAXKEYSIZE,nullptr);
            }
        };

        class SAML_DLLLOCAL DisplayNameImpl : public virtual DisplayName, public localizedNameTypeImpl
        {
        public:
            virtual ~DisplayNameImpl() {}

            DisplayNameImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            DisplayNameImpl(const DisplayNameImpl& src) : AbstractXMLObject(src), localizedNameTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(DisplayName);
        };

        class SAML_DLLLOCAL DescriptionImpl : public virtual Description, public localizedNameTypeImpl
        {
        public:
            virtual ~DescriptionImpl() {}

            DescriptionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            DescriptionImpl(const DescriptionImpl& src) : AbstractXMLObject(src), localizedNameTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(Description);
        };

        class SAML_DLLLOCAL InformationURLImpl : public virtual InformationURL, public localizedURITypeImpl
        {
        public:
            virtual ~InformationURLImpl() {}

            InformationURLImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            InformationURLImpl(const InformationURLImpl& src) : AbstractXMLObject(src), localizedURITypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(InformationURL);
        };

        class SAML_DLLLOCAL PrivacyStatementURLImpl : public virtual PrivacyStatementURL, public localizedURITypeImpl
        {
        public:
            virtual ~PrivacyStatementURLImpl() {}

            PrivacyStatementURLImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            PrivacyStatementURLImpl(const PrivacyStatementURLImpl& src) : AbstractXMLObject(src), localizedURITypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(PrivacyStatementURL);
        };

        class SAML_DLLLOCAL KeywordsImpl : public virtual Keywords,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Lang=nullptr;
                m_LangPrefix=nullptr;
            }

        protected:
            KeywordsImpl() {
                init();
            }

        public:
            virtual ~KeywordsImpl() {
                XMLString::release(&m_Lang);
                XMLString::release(&m_LangPrefix);
            }

            KeywordsImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            KeywordsImpl(const KeywordsImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_FOREIGN_ATTRIB(Lang);
            }

            IMPL_XMLOBJECT_CLONE(Keywords);
            IMPL_XMLOBJECT_FOREIGN_ATTRIB(Lang,XMLCh);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                if (m_Lang && *m_Lang) {
                    DOMAttr* attr=domElement->getOwnerDocument()->createAttributeNS(xmlconstants::XML_NS, LANG_ATTRIB_NAME);
                    if (m_LangPrefix && *m_LangPrefix)
                        attr->setPrefix(m_LangPrefix);
                    else
                        attr->setPrefix(xmlconstants::XML_PREFIX);
                    attr->setNodeValue(m_Lang);
                    domElement->setAttributeNodeNS(attr);
                }
            }

            void processAttribute(const DOMAttr* attribute) {
                if (XMLHelper::isNodeNamed(attribute, xmlconstants::XML_NS, LANG_ATTRIB_NAME)) {
                    setLang(attribute->getValue());
                    const XMLCh* temp = attribute->getPrefix();
                    if (temp && *temp && !XMLString::equals(temp, xmlconstants::XML_NS))
                        m_LangPrefix = XMLString::replicate(temp);
                    return;
                }
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL LogoImpl : public virtual Logo,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Lang=nullptr;
                m_LangPrefix=nullptr;
                m_Height=nullptr;
                m_Width=nullptr;
            }

        protected:
            LogoImpl() {
                init();
            }

        public:
            virtual ~LogoImpl() {
                XMLString::release(&m_Lang);
                XMLString::release(&m_LangPrefix);
                XMLString::release(&m_Height);
                XMLString::release(&m_Width);
            }

            LogoImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            LogoImpl(const LogoImpl& src) : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_FOREIGN_ATTRIB(Lang);
                IMPL_CLONE_INTEGER_ATTRIB(Height);
                IMPL_CLONE_INTEGER_ATTRIB(Width);
            }

            IMPL_XMLOBJECT_CLONE(Logo);
            IMPL_XMLOBJECT_FOREIGN_ATTRIB(Lang,XMLCh);
            IMPL_INTEGER_ATTRIB(Height);
            IMPL_INTEGER_ATTRIB(Width);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                if (m_Lang && *m_Lang) {
                    DOMAttr* attr=domElement->getOwnerDocument()->createAttributeNS(xmlconstants::XML_NS, LANG_ATTRIB_NAME);
                    if (m_LangPrefix && *m_LangPrefix)
                        attr->setPrefix(m_LangPrefix);
                    else
                        attr->setPrefix(xmlconstants::XML_PREFIX);
                    attr->setNodeValue(m_Lang);
                    domElement->setAttributeNodeNS(attr);
                }
                MARSHALL_INTEGER_ATTRIB(Height,HEIGHT,nullptr);
                MARSHALL_INTEGER_ATTRIB(Width,WIDTH,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                if (XMLHelper::isNodeNamed(attribute, xmlconstants::XML_NS, LANG_ATTRIB_NAME)) {
                    setLang(attribute->getValue());
                    const XMLCh* temp = attribute->getPrefix();
                    if (temp && *temp && !XMLString::equals(temp, xmlconstants::XML_NS))
                        m_LangPrefix = XMLString::replicate(temp);
                    return;
                }
                PROC_INTEGER_ATTRIB(Height,HEIGHT,nullptr);
                PROC_INTEGER_ATTRIB(Width,WIDTH,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL UIInfoImpl : public virtual UIInfo,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~UIInfoImpl() {}

            UIInfoImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            UIInfoImpl(const UIInfoImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                IMPL_CLONE_CHILDBAG_BEGIN;
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(DisplayName);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(Description);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(Keywords);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(Logo);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(InformationURL);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(PrivacyStatementURL);
                    IMPL_CLONE_XMLOBJECT_CHILD_IN_BAG(UnknownXMLObject);
                IMPL_CLONE_CHILDBAG_END;
            }

            IMPL_XMLOBJECT_CLONE(UIInfo);
            IMPL_TYPED_CHILDREN(DisplayName,m_children.end());
            IMPL_TYPED_CHILDREN(Description,m_children.end());
			IMPL_TYPED_CHILDREN(Keywords,m_children.end());
            IMPL_TYPED_CHILDREN(Logo,m_children.end());
            IMPL_TYPED_CHILDREN(InformationURL,m_children.end());
            IMPL_TYPED_CHILDREN(PrivacyStatementURL,m_children.end());
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(DisplayName,SAML20MD_UI_NS,false);
                PROC_TYPED_CHILDREN(Description,SAML20MD_UI_NS,false);
				PROC_TYPED_CHILDREN(Keywords,SAML20MD_UI_NS,false);
                PROC_TYPED_CHILDREN(Logo,SAML20MD_UI_NS,false);
                PROC_TYPED_CHILDREN(InformationURL,SAML20MD_UI_NS,false);
                PROC_TYPED_CHILDREN(PrivacyStatementURL,SAML20MD_UI_NS,false);

                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAML20MD_UI_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }

                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL DiscoHintsImpl : public virtual DiscoHints,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~DiscoHintsImpl() {}

            DiscoHintsImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            DiscoHintsImpl(const DiscoHintsImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                IMPL_CLONE_CHILDBAG_BEGIN;
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(IPHint);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(DomainHint);
                    IMPL_CLONE_TYPED_CHILD_IN_BAG(GeolocationHint);
                    IMPL_CLONE_XMLOBJECT_CHILD_IN_BAG(UnknownXMLObject);
                IMPL_CLONE_CHILDBAG_END;
            }

            IMPL_XMLOBJECT_CLONE(DiscoHints);
            IMPL_TYPED_CHILDREN(IPHint,m_children.end());
            IMPL_TYPED_CHILDREN(DomainHint,m_children.end());
            IMPL_TYPED_CHILDREN(GeolocationHint,m_children.end());
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(IPHint,SAML20MD_UI_NS,false);
                PROC_TYPED_CHILDREN(DomainHint,SAML20MD_UI_NS,false);
                PROC_TYPED_CHILDREN(GeolocationHint,SAML20MD_UI_NS,false);

                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAML20MD_UI_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }

                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL RegistrationInfoImpl : public virtual RegistrationInfo,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            list<XMLObject*>::iterator m_pos_UnknownChildren;

            void init() {
                m_RegistrationAuthority = nullptr;
                m_RegistrationInstant = nullptr;

                m_children.push_back(nullptr);
                m_pos_UnknownChildren = m_children.begin();
                ++m_pos_UnknownChildren;
            }

        protected:
            RegistrationInfoImpl() {
                init();
            }

        public:
            virtual ~RegistrationInfoImpl() {
                XMLString::release(&m_RegistrationAuthority);
                delete m_RegistrationInstant;
            }

            RegistrationInfoImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            RegistrationInfoImpl(const RegistrationInfoImpl& src)
                : AbstractXMLObject(src),
                AbstractAttributeExtensibleXMLObject(src),
                AbstractComplexElement(src),
                AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(RegistrationAuthority);
                IMPL_CLONE_ATTRIB(RegistrationInstant);
                IMPL_CLONE_TYPED_CHILDREN(RegistrationPolicy);
                IMPL_CLONE_XMLOBJECT_CHILDREN(UnknownXMLObject);
            }

            IMPL_XMLOBJECT_CLONE(RegistrationInfo);
            IMPL_STRING_ATTRIB(RegistrationAuthority);
            IMPL_DATETIME_ATTRIB(RegistrationInstant,0);
            IMPL_TYPED_CHILDREN(RegistrationPolicy,m_pos_UnknownChildren);
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),REGAUTHORITY_ATTRIB_NAME)) {
                        setRegistrationAuthority(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),REGINSTANT_ATTRIB_NAME)) {
                        setRegistrationInstant(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(RegistrationAuthority,REGAUTHORITY,nullptr);
                MARSHALL_DATETIME_ATTRIB(RegistrationInstant,REGINSTANT,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(RegistrationPolicy,SAML20MD_RPI_NS,false);
                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAML20MD_RPI_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL RegistrationPolicyImpl : public virtual RegistrationPolicy, public localizedURITypeImpl
        {
        public:
            virtual ~RegistrationPolicyImpl() {}

            RegistrationPolicyImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            RegistrationPolicyImpl(const RegistrationPolicyImpl& src) : AbstractXMLObject(src), localizedURITypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(RegistrationPolicy);
        };

        class SAML_DLLLOCAL PublicationPathImpl : public virtual PublicationPath,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {

        public:
            virtual ~PublicationPathImpl() {}

            PublicationPathImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            PublicationPathImpl(const PublicationPathImpl& src)
                : AbstractXMLObject(src),
                AbstractComplexElement(src),
                AbstractDOMCachingXMLObject(src) {

                IMPL_CLONE_TYPED_CHILDREN(Publication);
            }

            IMPL_XMLOBJECT_CLONE(PublicationPath);
            IMPL_TYPED_CHILDREN(Publication,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(Publication,SAML20MD_RPI_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL PublicationImpl : public virtual Publication,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Publisher=m_PublicationID=nullptr;
                m_CreationInstant=nullptr;
            }

        protected:
            PublicationImpl() {
                init();
            }

        public:
            virtual ~PublicationImpl() {
                XMLString::release(&m_Publisher);
                XMLString::release(&m_PublicationID);
                delete m_CreationInstant;
            }

            PublicationImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            PublicationImpl(const PublicationImpl& src)
                    : AbstractXMLObject(src),
                        AbstractSimpleElement(src),
                        AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Publisher);
                IMPL_CLONE_ATTRIB(CreationInstant);
                IMPL_CLONE_ATTRIB(PublicationID);
            }

            IMPL_XMLOBJECT_CLONE(Publication);
            IMPL_STRING_ATTRIB(Publisher);
            IMPL_DATETIME_ATTRIB(CreationInstant,0);
            IMPL_STRING_ATTRIB(PublicationID);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Publisher,PUBLISHER,nullptr);
                MARSHALL_DATETIME_ATTRIB(CreationInstant,CREATIONINSTANT,nullptr);
                MARSHALL_STRING_ATTRIB(PublicationID,PUBLICATIONID,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Publisher,PUBLISHER,nullptr);
                PROC_DATETIME_ATTRIB(CreationInstant,CREATIONINSTANT,nullptr);
                PROC_STRING_ATTRIB(PublicationID,PUBLICATIONID,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL PublicationInfoImpl : public virtual PublicationInfo,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            list<XMLObject*>::iterator m_pos_UnknownChildren;

            void init() {
                m_Publisher=m_PublicationID=nullptr;
                m_CreationInstant=nullptr;

                m_children.push_back(nullptr);
                m_pos_UnknownChildren = m_children.begin();
                ++m_pos_UnknownChildren;
            }

        protected:
            PublicationInfoImpl() {
                init();
            }

        public:
            virtual ~PublicationInfoImpl() {
                XMLString::release(&m_Publisher);
                XMLString::release(&m_PublicationID);
                delete m_CreationInstant;
            }

            PublicationInfoImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            PublicationInfoImpl(const PublicationInfoImpl& src)
                : AbstractXMLObject(src),
                AbstractAttributeExtensibleXMLObject(src),
                AbstractComplexElement(src),
                AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Publisher);
                IMPL_CLONE_ATTRIB(CreationInstant);
                IMPL_CLONE_ATTRIB(PublicationID);
                IMPL_CLONE_TYPED_CHILDREN(UsagePolicy);
                IMPL_CLONE_XMLOBJECT_CHILDREN(UnknownXMLObject);
            }

            IMPL_XMLOBJECT_CLONE(PublicationInfo);
            IMPL_STRING_ATTRIB(Publisher);
            IMPL_DATETIME_ATTRIB(CreationInstant,0);
            IMPL_STRING_ATTRIB(PublicationID);
            IMPL_TYPED_CHILDREN(UsagePolicy,m_pos_UnknownChildren);
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),PUBLISHER_ATTRIB_NAME)) {
                        setPublisher(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),CREATIONINSTANT_ATTRIB_NAME)) {
                        setCreationInstant(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),PUBLICATIONID_ATTRIB_NAME)) {
                        setPublicationID(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Publisher,PUBLISHER,nullptr);
                MARSHALL_DATETIME_ATTRIB(CreationInstant,CREATIONINSTANT,nullptr);
                MARSHALL_STRING_ATTRIB(PublicationID,PUBLICATIONID,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(UsagePolicy,SAML20MD_RPI_NS,false);
                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAML20MD_RPI_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Publisher,PUBLISHER,nullptr);
                PROC_DATETIME_ATTRIB(CreationInstant,CREATIONINSTANT,nullptr);
                PROC_STRING_ATTRIB(PublicationID,PUBLICATIONID,nullptr);
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL UsagePolicyImpl : public virtual UsagePolicy, public localizedURITypeImpl
        {
        public:
            virtual ~UsagePolicyImpl() {}

            UsagePolicyImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            UsagePolicyImpl(const UsagePolicyImpl& src) : AbstractXMLObject(src), localizedURITypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(UsagePolicy);
        };

    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

IMPL_ELEMENT_QNAME(IDPSSODescriptor, SAML20MD_NS, SAML20MD_PREFIX);
IMPL_ELEMENT_QNAME(SPSSODescriptor, SAML20MD_NS, SAML20MD_PREFIX);
IMPL_ELEMENT_QNAME(AuthnAuthorityDescriptor, SAML20MD_NS, SAML20MD_PREFIX);
IMPL_ELEMENT_QNAME(AttributeAuthorityDescriptor, SAML20MD_NS, SAML20MD_PREFIX);
IMPL_ELEMENT_QNAME(PDPDescriptor, SAML20MD_NS, SAML20MD_PREFIX);
IMPL_TYPE_QNAME(AuthnQueryDescriptorType, SAML20MD_QUERY_EXT_NS, SAML20MD_QUERY_EXT_PREFIX);
IMPL_TYPE_QNAME(AttributeQueryDescriptorType, SAML20MD_QUERY_EXT_NS, SAML20MD_QUERY_EXT_PREFIX);
IMPL_TYPE_QNAME(AuthzDecisionQueryDescriptorType, SAML20MD_QUERY_EXT_NS, SAML20MD_QUERY_EXT_PREFIX);

// Builder Implementations

IMPL_XMLOBJECTBUILDER(AdditionalMetadataLocation);
IMPL_XMLOBJECTBUILDER(AffiliateMember);
IMPL_XMLOBJECTBUILDER(AffiliationDescriptor);
IMPL_XMLOBJECTBUILDER(ArtifactResolutionService);
IMPL_XMLOBJECTBUILDER(AssertionConsumerService);
IMPL_XMLOBJECTBUILDER(AssertionIDRequestService);
IMPL_XMLOBJECTBUILDER(AttributeAuthorityDescriptor);
IMPL_XMLOBJECTBUILDER(AttributeConsumingService);
IMPL_XMLOBJECTBUILDER(AttributeProfile);
IMPL_XMLOBJECTBUILDER(AttributeQueryDescriptorType);
IMPL_XMLOBJECTBUILDER(AttributeService);
IMPL_XMLOBJECTBUILDER(AuthnAuthorityDescriptor);
IMPL_XMLOBJECTBUILDER(AuthnQueryDescriptorType);
IMPL_XMLOBJECTBUILDER(AuthnQueryService);
IMPL_XMLOBJECTBUILDER(AuthzDecisionQueryDescriptorType);
IMPL_XMLOBJECTBUILDER(AuthzService);
IMPL_XMLOBJECTBUILDER(Company);
IMPL_XMLOBJECTBUILDER(ContactPerson);
IMPL_XMLOBJECTBUILDER(EmailAddress);
IMPL_XMLOBJECTBUILDER(EndpointType);
IMPL_XMLOBJECTBUILDER(EntitiesDescriptor);
IMPL_XMLOBJECTBUILDER(EntityDescriptor);
IMPL_XMLOBJECTBUILDER(Extensions);
IMPL_XMLOBJECTBUILDER(GivenName);
IMPL_XMLOBJECTBUILDER(IDPSSODescriptor);
IMPL_XMLOBJECTBUILDER(IndexedEndpointType);
IMPL_XMLOBJECTBUILDER(KeyDescriptor);
IMPL_XMLOBJECTBUILDER(localizedNameType);
IMPL_XMLOBJECTBUILDER(localizedURIType);
IMPL_XMLOBJECTBUILDER(ManageNameIDService);
IMPL_XMLOBJECTBUILDER(NameIDFormat);
IMPL_XMLOBJECTBUILDER(NameIDMappingService);
IMPL_XMLOBJECTBUILDER(Organization);
IMPL_XMLOBJECTBUILDER(OrganizationName);
IMPL_XMLOBJECTBUILDER(OrganizationDisplayName);
IMPL_XMLOBJECTBUILDER(OrganizationURL);
IMPL_XMLOBJECTBUILDER(PDPDescriptor);
IMPL_XMLOBJECTBUILDER(RequestedAttribute);
IMPL_XMLOBJECTBUILDER(ServiceDescription);
IMPL_XMLOBJECTBUILDER(ServiceName);
IMPL_XMLOBJECTBUILDER(SingleLogoutService);
IMPL_XMLOBJECTBUILDER(SingleSignOnService);
IMPL_XMLOBJECTBUILDER(SPSSODescriptor);
IMPL_XMLOBJECTBUILDER(SurName);
IMPL_XMLOBJECTBUILDER(TelephoneNumber);

IMPL_XMLOBJECTBUILDER(ActionNamespace);
IMPL_XMLOBJECTBUILDER(SourceID);
IMPL_XMLOBJECTBUILDER(DiscoveryResponse);
IMPL_XMLOBJECTBUILDER(RequestInitiator);
IMPL_XMLOBJECTBUILDER(EntityAttributes);
IMPL_XMLOBJECTBUILDER(DigestMethod);
IMPL_XMLOBJECTBUILDER(SigningMethod);
IMPL_XMLOBJECTBUILDER(DisplayName);
IMPL_XMLOBJECTBUILDER(Description);
IMPL_XMLOBJECTBUILDER(Keywords);
IMPL_XMLOBJECTBUILDER(Logo);
IMPL_XMLOBJECTBUILDER(InformationURL);
IMPL_XMLOBJECTBUILDER(PrivacyStatementURL);
IMPL_XMLOBJECTBUILDER(UIInfo);
IMPL_XMLOBJECTBUILDER(IPHint);
IMPL_XMLOBJECTBUILDER(DomainHint);
IMPL_XMLOBJECTBUILDER(GeolocationHint);
IMPL_XMLOBJECTBUILDER(DiscoHints);
IMPL_XMLOBJECTBUILDER(RegistrationInfo);
IMPL_XMLOBJECTBUILDER(RegistrationPolicy);
IMPL_XMLOBJECTBUILDER(Publication);
IMPL_XMLOBJECTBUILDER(PublicationPath);
IMPL_XMLOBJECTBUILDER(PublicationInfo);
IMPL_XMLOBJECTBUILDER(UsagePolicy);

#ifdef HAVE_COVARIANT_RETURNS
RoleDescriptor* RoleDescriptorBuilder::buildObject(
#else
xmltooling::XMLObject* RoleDescriptorBuilder::buildObject(
#endif
    const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType
    ) const
{
    return new RoleDescriptorTypeImpl(nsURI,localName,prefix,schemaType);
}

const DigestMethod* RoleDescriptor::getDigestMethod() const
{
    bool roleLevel = false;
    XMLToolingConfig& conf = XMLToolingConfig::getConfig();

    if (getExtensions()) {
        const vector<XMLObject*>& exts = const_cast<const Extensions*>(getExtensions())->getUnknownXMLObjects();
        for (vector<XMLObject*>::const_iterator i = exts.begin(); i != exts.end(); ++i) {
            const opensaml::saml2md::DigestMethod* dm = dynamic_cast<opensaml::saml2md::DigestMethod*>(*i);
            if (dm) {
                if (dm->getAlgorithm() && conf.isXMLAlgorithmSupported(dm->getAlgorithm(), XMLToolingConfig::ALGTYPE_DIGEST))
                    return dm;
                roleLevel = true;
            }
        }
    }

    if (!roleLevel) {
        const EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(getParent());
        if (entity && entity->getExtensions()) {
            const vector<XMLObject*>& exts = const_cast<const Extensions*>(entity->getExtensions())->getUnknownXMLObjects();
            for (vector<XMLObject*>::const_iterator i = exts.begin(); i != exts.end(); ++i) {
                const opensaml::saml2md::DigestMethod* dm = dynamic_cast<opensaml::saml2md::DigestMethod*>(*i);
                if (dm && dm->getAlgorithm() && conf.isXMLAlgorithmSupported(dm->getAlgorithm(), XMLToolingConfig::ALGTYPE_DIGEST))
                    return dm;
            }
        }
    }

    return nullptr;
}

pair<const SigningMethod*,const Credential*> RoleDescriptor::getSigningMethod(const CredentialResolver& resolver, CredentialCriteria& cc) const
{
    bool roleLevel = false;
    XMLToolingConfig& conf = XMLToolingConfig::getConfig();

    if (getExtensions()) {
        const vector<XMLObject*>& exts = const_cast<const Extensions*>(getExtensions())->getUnknownXMLObjects();
        for (vector<XMLObject*>::const_iterator i = exts.begin(); i != exts.end(); ++i) {
            const SigningMethod* sm = dynamic_cast<SigningMethod*>(*i);
            if (sm) {
                roleLevel = true;
                if (sm->getAlgorithm() && conf.isXMLAlgorithmSupported(sm->getAlgorithm(), XMLToolingConfig::ALGTYPE_SIGN)) {
                    cc.setXMLAlgorithm(sm->getAlgorithm());
                    pair<bool,int> minsize = sm->getMinKeySize(), maxsize = sm->getMaxKeySize();
                    if (minsize.first || maxsize.first) {
                        cc.setKeySize(minsize.first ? minsize.second : 0);
                        cc.setMaxKeySize(maxsize.first ? maxsize.second : UINT_MAX);
                    }
                    else {
                        cc.setKeySize(0);
                        cc.setMaxKeySize(0);
                    }
                    const Credential* cred = resolver.resolve(&cc);
                    if (cred)
                        return make_pair(sm, cred);
                }
            }
        }
    }

    if (!roleLevel) {
        const EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(getParent());
        if (entity && entity->getExtensions()) {
            const vector<XMLObject*>& exts = const_cast<const Extensions*>(entity->getExtensions())->getUnknownXMLObjects();
            for (vector<XMLObject*>::const_iterator i = exts.begin(); i != exts.end(); ++i) {
                const SigningMethod* sm = dynamic_cast<SigningMethod*>(*i);
                if (sm) {
                    if (sm->getAlgorithm() && conf.isXMLAlgorithmSupported(sm->getAlgorithm(), XMLToolingConfig::ALGTYPE_SIGN)) {
                        cc.setXMLAlgorithm(sm->getAlgorithm());
                        pair<bool,int> minsize = sm->getMinKeySize(), maxsize = sm->getMaxKeySize();
                        if (minsize.first || maxsize.first) {
                            cc.setKeySize(minsize.first ? minsize.second : 0);
                            cc.setMaxKeySize(maxsize.first ? maxsize.second : UINT_MAX);
                        }
                        else {
                            cc.setKeySize(0);
                            cc.setMaxKeySize(0);
                        }
                        const Credential* cred = resolver.resolve(&cc);
                        if (cred)
                            return make_pair(sm, cred);
                    }
                }
            }
        }
    }

    cc.setKeySize(0);
    cc.setMaxKeySize(0);
    cc.setXMLAlgorithm(nullptr);
    return pair<const SigningMethod*,const Credential*>(nullptr, resolver.resolve(&cc));
}

const XMLCh ActionNamespace::LOCAL_NAME[] =             UNICODE_LITERAL_15(A,c,t,i,o,n,N,a,m,e,s,p,a,c,e);
const XMLCh AdditionalMetadataLocation::LOCAL_NAME[] =  UNICODE_LITERAL_26(A,d,d,i,t,i,o,n,a,l,M,e,t,a,d,a,t,a,L,o,c,a,t,i,o,n);
const XMLCh AdditionalMetadataLocation::TYPE_NAME[] =   UNICODE_LITERAL_30(A,d,d,i,t,i,o,n,a,l,M,e,t,a,d,a,t,a,L,o,c,a,t,i,o,n,T,y,p,e);
const XMLCh AdditionalMetadataLocation::NAMESPACE_ATTRIB_NAME[] =   UNICODE_LITERAL_9(n,a,m,e,s,p,a,c,e);
const XMLCh AffiliateMember::LOCAL_NAME[] =             UNICODE_LITERAL_15(A,f,f,i,l,i,a,t,e,M,e,m,b,e,r);
const XMLCh AffiliationDescriptor::LOCAL_NAME[] =       UNICODE_LITERAL_21(A,f,f,i,l,i,a,t,i,o,n,D,e,s,c,r,i,p,t,o,r);
const XMLCh AffiliationDescriptor::TYPE_NAME[] =        UNICODE_LITERAL_25(A,f,f,i,l,i,a,t,i,o,n,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh AffiliationDescriptor::ID_ATTRIB_NAME[] =   UNICODE_LITERAL_2(I,D);
const XMLCh AffiliationDescriptor::AFFILIATIONOWNERID_ATTRIB_NAME[] =   UNICODE_LITERAL_18(a,f,f,i,l,i,a,t,i,o,n,O,w,n,e,r,I,D);
const XMLCh ArtifactResolutionService::LOCAL_NAME[] =   UNICODE_LITERAL_25(A,r,t,i,f,a,c,t,R,e,s,o,l,u,t,i,o,n,S,e,r,v,i,c,e);
const XMLCh AssertionConsumerService::LOCAL_NAME[] =    UNICODE_LITERAL_24(A,s,s,e,r,t,i,o,n,C,o,n,s,u,m,e,r,S,e,r,v,i,c,e);
const XMLCh AssertionIDRequestService::LOCAL_NAME[] =   UNICODE_LITERAL_25(A,s,s,e,r,t,i,o,n,I,D,R,e,q,u,e,s,t,S,e,r,v,i,c,e);
const XMLCh AttributeAuthorityDescriptor::LOCAL_NAME[] =UNICODE_LITERAL_28(A,t,t,r,i,b,u,t,e,A,u,t,h,o,r,i,t,y,D,e,s,c,r,i,p,t,o,r);
const XMLCh AttributeAuthorityDescriptor::TYPE_NAME[] = UNICODE_LITERAL_32(A,t,t,r,i,b,u,t,e,A,u,t,h,o,r,i,t,y,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh AttributeConsumingService::LOCAL_NAME[] =   UNICODE_LITERAL_25(A,t,t,r,i,b,u,t,e,C,o,n,s,u,m,i,n,g,S,e,r,v,i,c,e);
const XMLCh AttributeConsumingService::TYPE_NAME[] =    UNICODE_LITERAL_29(A,t,t,r,i,b,u,t,e,C,o,n,s,u,m,i,n,g,S,e,r,v,i,c,e,T,y,p,e);
const XMLCh AttributeConsumingService::INDEX_ATTRIB_NAME[] =    UNICODE_LITERAL_5(i,n,d,e,x);
const XMLCh AttributeConsumingService::ISDEFAULT_ATTRIB_NAME[] =    UNICODE_LITERAL_9(i,s,D,e,f,a,u,l,t);
const XMLCh AttributeProfile::LOCAL_NAME[] =            UNICODE_LITERAL_16(A,t,t,r,i,b,u,t,e,P,r,o,f,i,l,e);
const XMLCh AttributeQueryDescriptorType::LOCAL_NAME[] =UNICODE_LITERAL_14(R,o,l,e,D,e,s,c,r,i,p,t,o,r);
const XMLCh AttributeQueryDescriptorType::TYPE_NAME[] = UNICODE_LITERAL_28(A,t,t,r,i,b,u,t,e,Q,u,e,r,y,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh AttributeService::LOCAL_NAME[] =            UNICODE_LITERAL_16(A,t,t,r,i,b,u,t,e,S,e,r,v,i,c,e);
const XMLCh AuthnAuthorityDescriptor::LOCAL_NAME[] =    UNICODE_LITERAL_24(A,u,t,h,n,A,u,t,h,o,r,i,t,y,D,e,s,c,r,i,p,t,o,r);
const XMLCh AuthnAuthorityDescriptor::TYPE_NAME[] =     UNICODE_LITERAL_28(A,u,t,h,n,A,u,t,h,o,r,i,t,y,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh AuthnQueryDescriptorType::LOCAL_NAME[] =    UNICODE_LITERAL_14(R,o,l,e,D,e,s,c,r,i,p,t,o,r);
const XMLCh AuthnQueryDescriptorType::TYPE_NAME[] =     UNICODE_LITERAL_24(A,u,t,h,n,Q,u,e,r,y,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh AuthnQueryService::LOCAL_NAME[] =           UNICODE_LITERAL_17(A,u,t,h,n,Q,u,e,r,y,S,e,r,v,i,c,e);
const XMLCh AuthzDecisionQueryDescriptorType::LOCAL_NAME[] =    UNICODE_LITERAL_14(R,o,l,e,D,e,s,c,r,i,p,t,o,r);
const XMLCh AuthzDecisionQueryDescriptorType::TYPE_NAME[] = UNICODE_LITERAL_32(A,u,t,h,z,D,e,c,i,s,i,o,n,Q,u,e,r,y,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh AuthzService::LOCAL_NAME[] =                UNICODE_LITERAL_12(A,u,t,h,z,S,e,r,v,i,c,e);
const XMLCh CacheableSAMLObject::CACHEDURATION_ATTRIB_NAME[] =  UNICODE_LITERAL_13(c,a,c,h,e,D,u,r,a,t,i,o,n);
const XMLCh Company::LOCAL_NAME[] =                     UNICODE_LITERAL_7(C,o,m,p,a,n,y);
const XMLCh ContactPerson::LOCAL_NAME[] =               UNICODE_LITERAL_13(C,o,n,t,a,c,t,P,e,r,s,o,n);
const XMLCh ContactPerson::TYPE_NAME[] =                UNICODE_LITERAL_11(C,o,n,t,a,c,t,T,y,p,e);
const XMLCh ContactPerson::CONTACTTYPE_ATTRIB_NAME[] =  UNICODE_LITERAL_11(c,o,n,t,a,c,t,T,y,p,e);
const XMLCh ContactPerson::CONTACT_TECHNICAL[] =        UNICODE_LITERAL_9(t,e,c,h,n,i,c,a,l);
const XMLCh ContactPerson::CONTACT_SUPPORT[] =          UNICODE_LITERAL_7(s,u,p,p,o,r,t);
const XMLCh ContactPerson::CONTACT_ADMINISTRATIVE[] =   UNICODE_LITERAL_14(a,d,m,i,n,i,s,t,r,a,t,i,v,e);
const XMLCh ContactPerson::CONTACT_BILLING[] =          UNICODE_LITERAL_7(b,i,l,l,i,n,g);
const XMLCh ContactPerson::CONTACT_OTHER[] =            UNICODE_LITERAL_5(o,t,h,e,r);
const XMLCh Description::LOCAL_NAME[] =                 UNICODE_LITERAL_11(D,e,s,c,r,i,p,t,i,o,n);
const XMLCh DigestMethod::LOCAL_NAME[] =                UNICODE_LITERAL_12(D,i,g,e,s,t,M,e,t,h,o,d);
const XMLCh DigestMethod::TYPE_NAME[] =                 UNICODE_LITERAL_16(D,i,g,e,s,t,M,e,t,h,o,d,T,y,p,e);
const XMLCh DigestMethod::ALGORITHM_ATTRIB_NAME[] =     UNICODE_LITERAL_9(A,l,g,o,r,i,t,h,m);
const XMLCh DiscoHints::LOCAL_NAME[] =                  UNICODE_LITERAL_10(D,i,s,c,o,H,i,n,t,s);
const XMLCh DiscoHints::TYPE_NAME[] =                   UNICODE_LITERAL_14(D,i,s,c,o,H,i,n,t,s,T,y,p,e);
const XMLCh DiscoveryResponse::LOCAL_NAME[] =           UNICODE_LITERAL_17(D,i,s,c,o,v,e,r,y,R,e,s,p,o,n,s,e);
const XMLCh DisplayName::LOCAL_NAME[] =                 UNICODE_LITERAL_11(D,i,s,p,l,a,y,N,a,m,e);
const XMLCh DomainHint::LOCAL_NAME[] =                  UNICODE_LITERAL_10(D,o,m,a,i,n,H,i,n,t);
const XMLCh EmailAddress::LOCAL_NAME[] =                UNICODE_LITERAL_12(E,m,a,i,l,A,d,d,r,e,s,s);
const XMLCh EndpointType::LOCAL_NAME[] =                {chNull};
const XMLCh EndpointType::TYPE_NAME[] =                 UNICODE_LITERAL_12(E,n,d,p,o,i,n,t,T,y,p,e);
const XMLCh EndpointType::BINDING_ATTRIB_NAME[] =       UNICODE_LITERAL_7(B,i,n,d,i,n,g);
const XMLCh EndpointType::LOCATION_ATTRIB_NAME[] =      UNICODE_LITERAL_8(L,o,c,a,t,i,o,n);
const XMLCh EndpointType::RESPONSELOCATION_ATTRIB_NAME[] =  UNICODE_LITERAL_16(R,e,s,p,o,n,s,e,L,o,c,a,t,i,o,n);
const XMLCh EntitiesDescriptor::LOCAL_NAME[] =          UNICODE_LITERAL_18(E,n,t,i,t,i,e,s,D,e,s,c,r,i,p,t,o,r);
const XMLCh EntitiesDescriptor::TYPE_NAME[] =           UNICODE_LITERAL_22(E,n,t,i,t,i,e,s,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh EntitiesDescriptor::ID_ATTRIB_NAME[] =      UNICODE_LITERAL_2(I,D);
const XMLCh EntitiesDescriptor::NAME_ATTRIB_NAME[] =    UNICODE_LITERAL_4(N,a,m,e);
const XMLCh EntityDescriptor::LOCAL_NAME[] =            UNICODE_LITERAL_16(E,n,t,i,t,y,D,e,s,c,r,i,p,t,o,r);
const XMLCh EntityDescriptor::TYPE_NAME[] =             UNICODE_LITERAL_20(E,n,t,i,t,y,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh EntityDescriptor::ID_ATTRIB_NAME[] =        UNICODE_LITERAL_2(I,D);
const XMLCh EntityDescriptor::ENTITYID_ATTRIB_NAME[] =  UNICODE_LITERAL_8(e,n,t,i,t,y,I,D);
const XMLCh EntityAttributes::LOCAL_NAME[] =            UNICODE_LITERAL_16(E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,s);
const XMLCh EntityAttributes::TYPE_NAME[] =             UNICODE_LITERAL_20(E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,s,T,y,p,e);
const XMLCh Extensions::LOCAL_NAME[] =                  UNICODE_LITERAL_10(E,x,t,e,n,s,i,o,n,s);
const XMLCh Extensions::TYPE_NAME[] =                   UNICODE_LITERAL_14(E,x,t,e,n,s,i,o,n,s,T,y,p,e);
const XMLCh GeolocationHint::LOCAL_NAME[] =             UNICODE_LITERAL_15(G,e,o,l,o,c,a,t,i,o,n,H,i,n,t);
const XMLCh GivenName::LOCAL_NAME[] =                   UNICODE_LITERAL_9(G,i,v,e,n,N,a,m,e);
const XMLCh IDPSSODescriptor::LOCAL_NAME[] =            UNICODE_LITERAL_16(I,D,P,S,S,O,D,e,s,c,r,i,p,t,o,r);
const XMLCh IDPSSODescriptor::TYPE_NAME[] =             UNICODE_LITERAL_20(I,D,P,S,S,O,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh IDPSSODescriptor::WANTAUTHNREQUESTSSIGNED_ATTRIB_NAME[] =   UNICODE_LITERAL_23(W,a,n,t,A,u,t,h,n,R,e,q,u,e,s,t,s,S,i,g,n,e,d);
const XMLCh IndexedEndpointType::LOCAL_NAME[] =         {chNull};
const XMLCh IndexedEndpointType::TYPE_NAME[] =          UNICODE_LITERAL_19(I,n,d,e,x,e,d,E,n,d,p,o,i,n,t,T,y,p,e);
const XMLCh IndexedEndpointType::INDEX_ATTRIB_NAME[] =  UNICODE_LITERAL_5(i,n,d,e,x);
const XMLCh IndexedEndpointType::ISDEFAULT_ATTRIB_NAME[] =  UNICODE_LITERAL_9(i,s,D,e,f,a,u,l,t);
const XMLCh InformationURL::LOCAL_NAME[] =              UNICODE_LITERAL_14(I,n,f,o,r,m,a,t,i,o,n,U,R,L);
const XMLCh IPHint::LOCAL_NAME[] =                      UNICODE_LITERAL_6(I,P,H,i,n,t);
const XMLCh KeyDescriptor::LOCAL_NAME[] =               UNICODE_LITERAL_13(K,e,y,D,e,s,c,r,i,p,t,o,r);
const XMLCh KeyDescriptor::TYPE_NAME[] =                UNICODE_LITERAL_17(K,e,y,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh KeyDescriptor::USE_ATTRIB_NAME[] =          UNICODE_LITERAL_3(u,s,e);
const XMLCh KeyDescriptor::KEYTYPE_ENCRYPTION[] =       UNICODE_LITERAL_10(e,n,c,r,y,p,t,i,o,n);
const XMLCh KeyDescriptor::KEYTYPE_SIGNING[] =          UNICODE_LITERAL_7(s,i,g,n,i,n,g);
const XMLCh Keywords::LOCAL_NAME[] =					UNICODE_LITERAL_8(K,e,y,w,o,r,d,s);
const XMLCh Keywords::TYPE_NAME[] =						UNICODE_LITERAL_12(K,e,y,w,o,r,d,s,T,y,p,e);
const XMLCh Keywords::LANG_ATTRIB_NAME[] =              UNICODE_LITERAL_4(l,a,n,g);
const XMLCh Logo::LOCAL_NAME[] =                        UNICODE_LITERAL_4(L,o,g,o);
const XMLCh Logo::TYPE_NAME[] =                         UNICODE_LITERAL_8(L,o,g,o,T,y,p,e);
const XMLCh Logo::LANG_ATTRIB_NAME[] =                  UNICODE_LITERAL_4(l,a,n,g);
const XMLCh Logo::HEIGHT_ATTRIB_NAME[] =                UNICODE_LITERAL_6(h,e,i,g,h,t);
const XMLCh Logo::WIDTH_ATTRIB_NAME[] =                 UNICODE_LITERAL_5(w,i,d,t,h);
const XMLCh localizedNameType::LOCAL_NAME[] =           {chNull};
const XMLCh localizedNameType::TYPE_NAME[] =            UNICODE_LITERAL_17(l,o,c,a,l,i,z,e,d,N,a,m,e,T,y,p,e);
const XMLCh localizedNameType::LANG_ATTRIB_NAME[] =     UNICODE_LITERAL_4(l,a,n,g);
const XMLCh localizedURIType::LOCAL_NAME[] =            {chNull};
const XMLCh localizedURIType::TYPE_NAME[] =             UNICODE_LITERAL_16(l,o,c,a,l,i,z,e,d,U,R,I,T,y,p,e);
const XMLCh localizedURIType::LANG_ATTRIB_NAME[] =      UNICODE_LITERAL_4(l,a,n,g);
const XMLCh ManageNameIDService::LOCAL_NAME[] =         UNICODE_LITERAL_19(M,a,n,a,g,e,N,a,m,e,I,D,S,e,r,v,i,c,e);
const XMLCh NameIDFormat::LOCAL_NAME[] =                UNICODE_LITERAL_12(N,a,m,e,I,D,F,o,r,m,a,t);
const XMLCh NameIDMappingService::LOCAL_NAME[] =        UNICODE_LITERAL_20(N,a,m,e,I,D,M,a,p,p,i,n,g,S,e,r,v,i,c,e);
const XMLCh Organization::LOCAL_NAME[] =                UNICODE_LITERAL_12(O,r,g,a,n,i,z,a,t,i,o,n);
const XMLCh Organization::TYPE_NAME[] =                 UNICODE_LITERAL_16(O,r,g,a,n,i,z,a,t,i,o,n,T,y,p,e);
const XMLCh OrganizationName::LOCAL_NAME[] =            UNICODE_LITERAL_16(O,r,g,a,n,i,z,a,t,i,o,n,N,a,m,e);
const XMLCh OrganizationDisplayName::LOCAL_NAME[] =     UNICODE_LITERAL_23(O,r,g,a,n,i,z,a,t,i,o,n,D,i,s,p,l,a,y,N,a,m,e);
const XMLCh OrganizationURL::LOCAL_NAME[] =             UNICODE_LITERAL_15(O,r,g,a,n,i,z,a,t,i,o,n,U,R,L);
const XMLCh PDPDescriptor::LOCAL_NAME[] =               UNICODE_LITERAL_13(P,D,P,D,e,s,c,r,i,p,t,o,r);
const XMLCh PDPDescriptor::TYPE_NAME[] =                UNICODE_LITERAL_17(P,D,P,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh PrivacyStatementURL::LOCAL_NAME[] =         UNICODE_LITERAL_19(P,r,i,v,a,c,y,S,t,a,t,e,m,e,n,t,U,R,L);
const XMLCh Publication::LOCAL_NAME[] =                 UNICODE_LITERAL_11(P,u,b,l,i,c,a,t,i,o,n);
const XMLCh Publication::TYPE_NAME[] =                  UNICODE_LITERAL_15(P,u,b,l,i,c,a,t,i,o,n,T,y,p,e);
const XMLCh Publication::PUBLISHER_ATTRIB_NAME[] =      UNICODE_LITERAL_9(p,u,b,l,i,s,h,e,r);
const XMLCh Publication::CREATIONINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_15(c,r,e,a,t,i,o,n,I,n,s,t,a,n,t);
const XMLCh Publication::PUBLICATIONID_ATTRIB_NAME[] =  UNICODE_LITERAL_13(p,u,b,l,i,c,a,t,i,o,n,I,d);
const XMLCh PublicationInfo::LOCAL_NAME[] =             UNICODE_LITERAL_15(P,u,b,l,i,c,a,t,i,o,n,I,n,f,o);
const XMLCh PublicationInfo::TYPE_NAME[] =              UNICODE_LITERAL_19(P,u,b,l,i,c,a,t,i,o,n,I,n,f,o,T,y,p,e);
const XMLCh PublicationInfo::PUBLISHER_ATTRIB_NAME[] =  UNICODE_LITERAL_9(p,u,b,l,i,s,h,e,r);
const XMLCh PublicationInfo::CREATIONINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_15(c,r,e,a,t,i,o,n,I,n,s,t,a,n,t);
const XMLCh PublicationInfo::PUBLICATIONID_ATTRIB_NAME[] = UNICODE_LITERAL_13(p,u,b,l,i,c,a,t,i,o,n,I,d);
const XMLCh PublicationPath::LOCAL_NAME[] =             UNICODE_LITERAL_15(P,u,b,l,i,c,a,t,i,o,n,P,a,t,h);
const XMLCh PublicationPath::TYPE_NAME[] =              UNICODE_LITERAL_19(P,u,b,l,i,c,a,t,i,o,n,P,a,t,h,T,y,p,e);
const XMLCh QueryDescriptorType::LOCAL_NAME[] =         {chNull};
const XMLCh QueryDescriptorType::TYPE_NAME[] =          UNICODE_LITERAL_19(Q,u,e,r,y,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh QueryDescriptorType::WANTASSERTIONSSIGNED_ATTRIB_NAME[] = UNICODE_LITERAL_20(W,a,n,t,A,s,s,e,r,t,i,o,n,s,S,i,g,n,e,d);
const XMLCh RegistrationInfo::LOCAL_NAME[] =            UNICODE_LITERAL_16(R,e,g,i,s,t,r,a,t,i,o,n,I,n,f,o);
const XMLCh RegistrationInfo::TYPE_NAME[] =             UNICODE_LITERAL_20(R,e,g,i,s,t,r,a,t,i,o,n,I,n,f,o,T,y,p,e);
const XMLCh RegistrationInfo::REGAUTHORITY_ATTRIB_NAME[] = UNICODE_LITERAL_21(r,e,g,i,s,t,r,a,t,i,o,n,A,u,t,h,o,r,i,t,y);
const XMLCh RegistrationInfo::REGINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_19(r,e,g,i,s,t,r,a,t,i,o,n,I,n,s,t,a,n,t);
const XMLCh RegistrationPolicy::LOCAL_NAME[] =          UNICODE_LITERAL_18(R,e,g,i,s,t,r,a,t,i,o,n,P,o,l,i,c,y);
const XMLCh RequestedAttribute::LOCAL_NAME[] =          UNICODE_LITERAL_18(R,e,q,u,e,s,t,e,d,A,t,t,r,i,b,u,t,e);
const XMLCh RequestedAttribute::TYPE_NAME[] =           UNICODE_LITERAL_22(R,e,q,u,e,s,t,e,d,A,t,t,r,i,b,u,t,e,T,y,p,e);
const XMLCh RequestedAttribute::ISREQUIRED_ATTRIB_NAME[] =  UNICODE_LITERAL_10(i,s,R,e,q,u,i,r,e,d);
const XMLCh RequestInitiator::LOCAL_NAME[] =            UNICODE_LITERAL_16(R,e,q,u,e,s,t,I,n,i,t,i,a,t,o,r);
const XMLCh RoleDescriptor::LOCAL_NAME[] =              UNICODE_LITERAL_14(R,o,l,e,D,e,s,c,r,i,p,t,o,r);
const XMLCh RoleDescriptor::ID_ATTRIB_NAME[] =          UNICODE_LITERAL_2(I,D);
const XMLCh RoleDescriptor::PROTOCOLSUPPORTENUMERATION_ATTRIB_NAME[] =  UNICODE_LITERAL_26(p,r,o,t,o,c,o,l,S,u,p,p,o,r,t,E,n,u,m,e,r,a,t,i,o,n);
const XMLCh RoleDescriptor::ERRORURL_ATTRIB_NAME[] =    UNICODE_LITERAL_8(e,r,r,o,r,U,R,L);
const XMLCh ServiceDescription::LOCAL_NAME[] =          UNICODE_LITERAL_18(S,e,r,v,i,c,e,D,e,s,c,r,i,p,t,i,o,n);
const XMLCh ServiceName::LOCAL_NAME[] =                 UNICODE_LITERAL_11(S,e,r,v,i,c,e,N,a,m,e);
const XMLCh SigningMethod::LOCAL_NAME[] =               UNICODE_LITERAL_13(S,i,g,n,i,n,g,M,e,t,h,o,d);
const XMLCh SigningMethod::TYPE_NAME[] =                UNICODE_LITERAL_17(S,i,g,n,i,n,g,M,e,t,h,o,d,T,y,p,e);
const XMLCh SigningMethod::ALGORITHM_ATTRIB_NAME[] =    UNICODE_LITERAL_9(A,l,g,o,r,i,t,h,m);
const XMLCh SigningMethod::MINKEYSIZE_ATTRIB_NAME[] =   UNICODE_LITERAL_10(M,i,n,K,e,y,S,i,z,e);
const XMLCh SigningMethod::MAXKEYSIZE_ATTRIB_NAME[] =   UNICODE_LITERAL_10(M,a,x,K,e,y,S,i,z,e);
const XMLCh SingleLogoutService::LOCAL_NAME[] =         UNICODE_LITERAL_19(S,i,n,g,l,e,L,o,g,o,u,t,S,e,r,v,i,c,e);
const XMLCh SingleSignOnService::LOCAL_NAME[] =         UNICODE_LITERAL_19(S,i,n,g,l,e,S,i,g,n,O,n,S,e,r,v,i,c,e);
const XMLCh SourceID::LOCAL_NAME[] =                    UNICODE_LITERAL_8(S,o,u,r,c,e,I,D);
const XMLCh SPSSODescriptor::LOCAL_NAME[] =             UNICODE_LITERAL_15(S,P,S,S,O,D,e,s,c,r,i,p,t,o,r);
const XMLCh SPSSODescriptor::TYPE_NAME[] =              UNICODE_LITERAL_19(S,P,S,S,O,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh SPSSODescriptor::AUTHNREQUESTSSIGNED_ATTRIB_NAME[] =    UNICODE_LITERAL_19(A,u,t,h,n,R,e,q,u,e,s,t,s,S,i,g,n,e,d);
const XMLCh SPSSODescriptor::WANTASSERTIONSSIGNED_ATTRIB_NAME[] =   UNICODE_LITERAL_20(W,a,n,t,A,s,s,e,r,t,i,o,n,s,S,i,g,n,e,d);
const XMLCh SSODescriptorType::LOCAL_NAME[] =           {chNull};
const XMLCh SSODescriptorType::TYPE_NAME[] =            UNICODE_LITERAL_17(S,S,O,D,e,s,c,r,i,p,t,o,r,T,y,p,e);
const XMLCh SurName::LOCAL_NAME[] =                     UNICODE_LITERAL_7(S,u,r,N,a,m,e);
const XMLCh TelephoneNumber::LOCAL_NAME[] =             UNICODE_LITERAL_15(T,e,l,e,p,h,o,n,e,N,u,m,b,e,r);
const XMLCh TimeBoundSAMLObject::VALIDUNTIL_ATTRIB_NAME[] =   UNICODE_LITERAL_10(v,a,l,i,d,U,n,t,i,l);
const XMLCh UIInfo::LOCAL_NAME[] =                      UNICODE_LITERAL_6(U,I,I,n,f,o);
const XMLCh UIInfo::TYPE_NAME[] =                       UNICODE_LITERAL_10(U,I,I,n,f,o,T,y,p,e);
const XMLCh UsagePolicy::LOCAL_NAME[] =                 UNICODE_LITERAL_11(U,s,a,g,e,P,o,l,i,c,y);
