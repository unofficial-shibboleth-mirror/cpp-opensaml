/*
 *  Copyright 2001-2010 Internet2
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
 * Assertions20Impl.cpp
 *
 * Implementation classes for SAML 2.0 Assertions schema.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/encryption/EncryptedKeyResolver.h"
#include "saml2/core/Assertions.h"
#include "signature/ContentReference.h"

#include <xmltooling/AbstractComplexElement.h>
#include <xmltooling/AbstractSimpleElement.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/util/XMLHelper.h>

#include <ctime>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml::saml2;
using namespace xmlencryption;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;
using xmlconstants::XSI_NS;
using xmlconstants::XMLSIG_NS;
using xmlconstants::XMLENC_NS;
using xmlconstants::XML_BOOL_NULL;
using samlconstants::SAML20_NS;
using samlconstants::SAML20_DELEGATION_CONDITION_NS;


#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {
    namespace saml2 {

        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AssertionIDRef);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AssertionURIRef);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,Audience);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AuthnContextClassRef);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AuthnContextDeclRef);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AuthenticatingAuthority);

        class SAML_DLLLOCAL NameIDTypeImpl : public virtual NameIDType,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Format=m_SPProvidedID=m_NameQualifier=m_SPNameQualifier=nullptr;
            }

        protected:
            NameIDTypeImpl() {
                init();
            }

        public:
            virtual ~NameIDTypeImpl() {
                XMLString::release(&m_NameQualifier);
                XMLString::release(&m_SPNameQualifier);
                XMLString::release(&m_Format);
                XMLString::release(&m_SPProvidedID);
            }

            NameIDTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            NameIDTypeImpl(const NameIDTypeImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setNameQualifier(src.getNameQualifier());
                setSPNameQualifier(src.getSPNameQualifier());
                setFormat(src.getFormat());
                setSPProvidedID(src.getSPProvidedID());
            }

            IMPL_XMLOBJECT_CLONE(NameIDType);
            IMPL_STRING_ATTRIB(NameQualifier);
            IMPL_STRING_ATTRIB(SPNameQualifier);
            IMPL_STRING_ATTRIB(Format);
            IMPL_STRING_ATTRIB(SPProvidedID);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER,nullptr);
                MARSHALL_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER,nullptr);
                MARSHALL_STRING_ATTRIB(Format,FORMAT,nullptr);
                MARSHALL_STRING_ATTRIB(SPProvidedID,SPPROVIDEDID,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER,nullptr);
                PROC_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER,nullptr);
                PROC_STRING_ATTRIB(Format,FORMAT,nullptr);
                PROC_STRING_ATTRIB(SPProvidedID,SPPROVIDEDID,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL NameIDImpl : public virtual NameID, public NameIDTypeImpl
        {
        public:
            virtual ~NameIDImpl() {}

            NameIDImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            NameIDImpl(const NameIDImpl& src) : AbstractXMLObject(src), NameIDTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE(NameID);
            NameIDType* cloneNameIDType() const {
                return new NameIDImpl(*this);
            }
        };

        class SAML_DLLLOCAL IssuerImpl : public virtual Issuer, public NameIDTypeImpl
        {
        public:
            virtual ~IssuerImpl() {}

            IssuerImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            IssuerImpl(const IssuerImpl& src) : AbstractXMLObject(src), NameIDTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE(Issuer);
            NameIDType* cloneNameIDType() const {
                return new IssuerImpl(*this);
            }
        };

        //TODO unit test for this
        //  - need to test encryption/decryption too, or already done in xmltooling ?
        class SAML_DLLLOCAL EncryptedElementTypeImpl : public virtual EncryptedElementType,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_EncryptedData=nullptr;
                m_children.push_back(nullptr);
                m_pos_EncryptedData=m_children.begin();
            }

        protected:
            EncryptedElementTypeImpl() {
                init();
            }

        public:
            virtual ~EncryptedElementTypeImpl() {}

            EncryptedElementTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            EncryptedElementTypeImpl(const EncryptedElementTypeImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                if (src.getEncryptedData())
                    setEncryptedData(src.getEncryptedData()->cloneEncryptedData());
                VectorOf(EncryptedKey) v=getEncryptedKeys();
                for (vector<EncryptedKey*>::const_iterator i=src.m_EncryptedKeys.begin(); i!=src.m_EncryptedKeys.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneEncryptedKey());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(EncryptedElementType);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption);
            IMPL_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption,XMLENC_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption,XMLENC_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL EncryptedIDImpl : public virtual EncryptedID, public EncryptedElementTypeImpl
        {
        public:
            virtual ~EncryptedIDImpl() {}

            EncryptedIDImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            EncryptedIDImpl(const EncryptedIDImpl& src) : AbstractXMLObject(src), EncryptedElementTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE(EncryptedID);
            EncryptedElementType* cloneEncryptedElementType() const {
                return new EncryptedIDImpl(*this);
            }
        };

        class SAML_DLLLOCAL ConditionImpl : public virtual Condition, public AnyElementImpl
        {
        public:
            virtual ~ConditionImpl() {}

            ConditionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            ConditionImpl(const ConditionImpl& src) : AbstractXMLObject(src), AnyElementImpl(src) {}

            IMPL_XMLOBJECT_CLONE(Condition);
        };

        class SAML_DLLLOCAL AudienceRestrictionImpl : public virtual AudienceRestriction,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AudienceRestrictionImpl() {}

            AudienceRestrictionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            AudienceRestrictionImpl(const AudienceRestrictionImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                VectorOf(Audience) v=getAudiences();
                for (vector<Audience*>::const_iterator i=src.m_Audiences.begin(); i!=src.m_Audiences.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAudience());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(AudienceRestriction);
            Condition* cloneCondition() const {
                return cloneAudienceRestriction();
            }
            IMPL_TYPED_CHILDREN(Audience,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(Audience,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL OneTimeUseImpl : public virtual OneTimeUse,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~OneTimeUseImpl() {}

            OneTimeUseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            OneTimeUseImpl(const OneTimeUseImpl& src)
                : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
            }

            IMPL_XMLOBJECT_CLONE(OneTimeUse);
            Condition* cloneCondition() const {
                return cloneOneTimeUse();
            }
        };

        class SAML_DLLLOCAL ProxyRestrictionImpl : public virtual ProxyRestriction,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~ProxyRestrictionImpl() {
                XMLString::release(&m_Count);
            }

            ProxyRestrictionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                m_Count=nullptr;
            }

            ProxyRestrictionImpl(const ProxyRestrictionImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                setCount(src.m_Count);
                VectorOf(Audience) v=getAudiences();
                for (vector<Audience*>::const_iterator i=src.m_Audiences.begin(); i!=src.m_Audiences.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAudience());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(ProxyRestriction);
            Condition* cloneCondition() const {
                return cloneProxyRestriction();
            }
            IMPL_TYPED_CHILDREN(Audience,m_children.end());
            IMPL_INTEGER_ATTRIB(Count);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_INTEGER_ATTRIB(Count,COUNT,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(Audience,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_INTEGER_ATTRIB(Count,COUNT,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL DelegateImpl : public virtual Delegate,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ConfirmationMethod=nullptr;
                m_DelegationInstant=nullptr;
                m_BaseID=nullptr;
                m_NameID=nullptr;
                m_EncryptedID=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_BaseID=m_children.begin();
                m_pos_NameID=m_pos_BaseID;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
            }
        public:
            virtual ~DelegateImpl() {
                XMLString::release(&m_ConfirmationMethod);
                delete m_DelegationInstant;
            }

            DelegateImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            DelegateImpl(const DelegateImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setConfirmationMethod(src.getConfirmationMethod());
                setDelegationInstant(src.getDelegationInstant());
                if (src.getBaseID())
                    setBaseID(src.getBaseID()->cloneBaseID());
                if (src.getNameID())
                    setNameID(src.getNameID()->cloneNameID());
                if (src.getEncryptedID())
                    setEncryptedID(src.getEncryptedID()->cloneEncryptedID());
            }

            IMPL_XMLOBJECT_CLONE(Delegate);
            IMPL_STRING_ATTRIB(ConfirmationMethod);
            IMPL_DATETIME_ATTRIB(DelegationInstant,0);
            IMPL_TYPED_CHILD(NameID);
            IMPL_TYPED_CHILD(BaseID);
            IMPL_TYPED_CHILD(EncryptedID);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(ConfirmationMethod,CONFIRMATIONMETHOD,nullptr);
                MARSHALL_DATETIME_ATTRIB(DelegationInstant,DELEGATIONINSTANT,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(BaseID,SAML20_NS,false);
                PROC_TYPED_CHILD(NameID,SAML20_NS,false);
                PROC_TYPED_CHILD(EncryptedID,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(ConfirmationMethod,CONFIRMATIONMETHOD,nullptr);
                PROC_DATETIME_ATTRIB(DelegationInstant,DELEGATIONINSTANT,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL DelegationRestrictionTypeImpl : public virtual DelegationRestrictionType,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~DelegationRestrictionTypeImpl() {}

            DelegationRestrictionTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            DelegationRestrictionTypeImpl(const DelegationRestrictionTypeImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                VectorOf(Delegate) v=getDelegates();
                for (vector<Delegate*>::const_iterator i=src.m_Delegates.begin(); i!=src.m_Delegates.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneDelegate());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(DelegationRestrictionType);
            Condition* cloneCondition() const {
                return cloneDelegationRestrictionType();
            }
            IMPL_TYPED_CHILDREN(Delegate,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(Delegate,SAML20_DELEGATION_CONDITION_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL ConditionsImpl : public virtual Conditions,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_NotBefore=m_NotOnOrAfter=nullptr;
            }
        public:
            virtual ~ConditionsImpl() {
                delete m_NotBefore;
                delete m_NotOnOrAfter;
            }

            ConditionsImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            ConditionsImpl(const ConditionsImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setNotBefore(src.getNotBefore());
                setNotOnOrAfter(src.getNotOnOrAfter());

                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        AudienceRestriction* arc=dynamic_cast<AudienceRestriction*>(*i);
                        if (arc) {
                            getAudienceRestrictions().push_back(arc->cloneAudienceRestriction());
                            continue;
                        }

                        OneTimeUse* dncc=dynamic_cast<OneTimeUse*>(*i);
                        if (dncc) {
                            getOneTimeUses().push_back(dncc->cloneOneTimeUse());
                            continue;
                        }

                        ProxyRestriction* prc=dynamic_cast<ProxyRestriction*>(*i);
                        if (prc) {
                            getProxyRestrictions().push_back(prc->cloneProxyRestriction());
                            continue;
                        }

                        Condition* c=dynamic_cast<Condition*>(*i);
                        if (c) {
                            getConditions().push_back(c->cloneCondition());
                            continue;
                        }
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(Conditions);
            IMPL_DATETIME_ATTRIB(NotBefore,0);
            IMPL_DATETIME_ATTRIB(NotOnOrAfter,SAMLTIME_MAX);
            IMPL_TYPED_CHILDREN(AudienceRestriction, m_children.end());
            IMPL_TYPED_CHILDREN(OneTimeUse,m_children.end());
            IMPL_TYPED_CHILDREN(ProxyRestriction, m_children.end());
            IMPL_TYPED_CHILDREN(Condition,m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_DATETIME_ATTRIB(NotBefore,NOTBEFORE,nullptr);
                MARSHALL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AudienceRestriction,SAML20_NS,false);
                PROC_TYPED_CHILDREN(OneTimeUse,SAML20_NS,false);
                PROC_TYPED_CHILDREN(ProxyRestriction,SAML20_NS,false);
                PROC_TYPED_CHILDREN(Condition,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_DATETIME_ATTRIB(NotBefore,NOTBEFORE,nullptr);
                PROC_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL SubjectConfirmationDataTypeImpl : public virtual SubjectConfirmationDataType, public virtual AbstractXMLObject
        {
            void init() {
                m_NotBefore=m_NotOnOrAfter=nullptr;
                m_Recipient=m_InResponseTo=m_Address=nullptr;
            }

        protected:
            SubjectConfirmationDataTypeImpl() {
                init();
            }

        public:
            virtual ~SubjectConfirmationDataTypeImpl() {
                delete m_NotBefore;
                delete m_NotOnOrAfter;
                XMLString::release(&m_Recipient);
                XMLString::release(&m_InResponseTo);
                XMLString::release(&m_Address);
            }

            SubjectConfirmationDataTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SubjectConfirmationDataTypeImpl(const SubjectConfirmationDataTypeImpl& src) : AbstractXMLObject(src) {
                init();
                setNotBefore(src.getNotBefore());
                setNotOnOrAfter(src.getNotOnOrAfter());
                setRecipient(src.getRecipient());
                setInResponseTo(src.getInResponseTo());
                setAddress(src.getAddress());
            }

            IMPL_DATETIME_ATTRIB(NotBefore,0);
            IMPL_DATETIME_ATTRIB(NotOnOrAfter,SAMLTIME_MAX);
            IMPL_STRING_ATTRIB(Recipient);
            IMPL_STRING_ATTRIB(InResponseTo);
            IMPL_STRING_ATTRIB(Address);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_DATETIME_ATTRIB(NotBefore,NOTBEFORE,nullptr);
                MARSHALL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
                MARSHALL_STRING_ATTRIB(Recipient,RECIPIENT,nullptr);
                MARSHALL_STRING_ATTRIB(InResponseTo,INRESPONSETO,nullptr);
                MARSHALL_STRING_ATTRIB(Address,ADDRESS,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_DATETIME_ATTRIB(NotBefore,NOTBEFORE,nullptr);
                PROC_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
                PROC_STRING_ATTRIB(Recipient,RECIPIENT,nullptr);
                PROC_STRING_ATTRIB(InResponseTo,INRESPONSETO,nullptr);
                PROC_STRING_ATTRIB(Address,ADDRESS,nullptr);
            }
        };

        class SAML_DLLLOCAL SubjectConfirmationDataImpl : public SubjectConfirmationData,
            public SubjectConfirmationDataTypeImpl, public AnyElementImpl
        {
        public:
            virtual ~SubjectConfirmationDataImpl() {}

            SubjectConfirmationDataImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            SubjectConfirmationDataImpl(const SubjectConfirmationDataImpl& src)
                    : AbstractXMLObject(src), SubjectConfirmationDataTypeImpl(src), AnyElementImpl(src) {
            }

            IMPL_XMLOBJECT_CLONE(SubjectConfirmationData);
            SubjectConfirmationDataType* cloneSubjectConfirmationDataType() const {
                return new SubjectConfirmationDataImpl(*this);
            }

            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),NOTBEFORE_ATTRIB_NAME)) {
                        setNotBefore(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),NOTONORAFTER_ATTRIB_NAME)) {
                        setNotOnOrAfter(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),RECIPIENT_ATTRIB_NAME)) {
                        setRecipient(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),INRESPONSETO_ATTRIB_NAME)) {
                        setInResponseTo(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),ADDRESS_ATTRIB_NAME)) {
                        setAddress(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                SubjectConfirmationDataTypeImpl::marshallAttributes(domElement);
                AnyElementImpl::marshallAttributes(domElement);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_DATETIME_ATTRIB(NotBefore,NOTBEFORE,nullptr);
                PROC_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
                PROC_STRING_ATTRIB(Recipient,RECIPIENT,nullptr);
                PROC_STRING_ATTRIB(InResponseTo,INRESPONSETO,nullptr);
                PROC_STRING_ATTRIB(Address,ADDRESS,nullptr);
                AnyElementImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL KeyInfoConfirmationDataTypeImpl : public virtual KeyInfoConfirmationDataType,
                public SubjectConfirmationDataTypeImpl,
                public AbstractComplexElement,
                public AbstractAttributeExtensibleXMLObject,
                public AbstractDOMCachingXMLObject,
                public AbstractXMLObjectMarshaller,
                public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~KeyInfoConfirmationDataTypeImpl() {}

            KeyInfoConfirmationDataTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            KeyInfoConfirmationDataTypeImpl(const KeyInfoConfirmationDataTypeImpl& src)
                    : AbstractXMLObject(src), SubjectConfirmationDataTypeImpl(src), AbstractComplexElement(src),
                        AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                VectorOf(KeyInfo) v=getKeyInfos();
                for (vector<KeyInfo*>::const_iterator i=src.m_KeyInfos.begin(); i!=src.m_KeyInfos.end(); ++i)
                    v.push_back((*i)->cloneKeyInfo());
            }

            IMPL_XMLOBJECT_CLONE(KeyInfoConfirmationDataType);
            SubjectConfirmationDataType* cloneSubjectConfirmationDataType() const {
                return new KeyInfoConfirmationDataTypeImpl(*this);
            }

            IMPL_TYPED_CHILDREN(KeyInfo,m_children.end());

        public:
            void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
                if (!qualifiedName.hasNamespaceURI()) {
                    if (XMLString::equals(qualifiedName.getLocalPart(),NOTBEFORE_ATTRIB_NAME)) {
                        setNotBefore(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),NOTONORAFTER_ATTRIB_NAME)) {
                        setNotOnOrAfter(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),RECIPIENT_ATTRIB_NAME)) {
                        setRecipient(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),INRESPONSETO_ATTRIB_NAME)) {
                        setInResponseTo(value);
                        return;
                    }
                    else if (XMLString::equals(qualifiedName.getLocalPart(),ADDRESS_ATTRIB_NAME)) {
                        setAddress(value);
                        return;
                    }
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                SubjectConfirmationDataTypeImpl::marshallAttributes(domElement);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(KeyInfo,XMLSIG_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                unmarshallExtensionAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL SubjectConfirmationImpl : public virtual SubjectConfirmation,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Method=nullptr;
                m_BaseID=nullptr;
                m_NameID=nullptr;
                m_EncryptedID=nullptr;
                m_SubjectConfirmationData=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_BaseID=m_children.begin();
                m_pos_NameID=m_pos_BaseID;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
                m_pos_SubjectConfirmationData=m_pos_EncryptedID;
                ++m_pos_SubjectConfirmationData;
            }
        public:
            virtual ~SubjectConfirmationImpl() {
                XMLString::release(&m_Method);
            }

            SubjectConfirmationImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SubjectConfirmationImpl(const SubjectConfirmationImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setMethod(src.getMethod());
                if (src.getBaseID())
                    setBaseID(src.getBaseID()->cloneBaseID());
                if (src.getNameID())
                    setNameID(src.getNameID()->cloneNameID());
                if (src.getEncryptedID())
                    setEncryptedID(src.getEncryptedID()->cloneEncryptedID());
                if (src.getSubjectConfirmationData())
                    setSubjectConfirmationData(src.getSubjectConfirmationData()->clone());
            }

            IMPL_XMLOBJECT_CLONE(SubjectConfirmation);
            IMPL_STRING_ATTRIB(Method);
            IMPL_TYPED_CHILD(BaseID);
            IMPL_TYPED_CHILD(NameID);
            IMPL_TYPED_CHILD(EncryptedID);
            IMPL_XMLOBJECT_CHILD(SubjectConfirmationData);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Method,METHOD,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(BaseID,SAML20_NS,false);
                PROC_TYPED_CHILD(NameID,SAML20_NS,false);
                PROC_TYPED_CHILD(EncryptedID,SAML20_NS,false);
                PROC_XMLOBJECT_CHILD(SubjectConfirmationData,SAML20_NS);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Method,METHOD,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL SubjectImpl : public virtual Subject,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_BaseID=nullptr;
                m_NameID=nullptr;
                m_EncryptedID=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_BaseID=m_children.begin();
                m_pos_NameID=m_pos_BaseID;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
            }
        public:
            virtual ~SubjectImpl() {}

            SubjectImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SubjectImpl(const SubjectImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                if (src.getBaseID())
                    setBaseID(src.getBaseID()->cloneBaseID());
                if (src.getNameID())
                    setNameID(src.getNameID()->cloneNameID());
                if (src.getEncryptedID())
                    setEncryptedID(src.getEncryptedID()->cloneEncryptedID());
                VectorOf(SubjectConfirmation) v=getSubjectConfirmations();
                for (vector<SubjectConfirmation*>::const_iterator i=src.m_SubjectConfirmations.begin(); i!=src.m_SubjectConfirmations.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneSubjectConfirmation());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(Subject);
            IMPL_TYPED_CHILD(NameID);
            IMPL_TYPED_CHILD(BaseID);
            IMPL_TYPED_CHILD(EncryptedID);
            IMPL_TYPED_CHILDREN(SubjectConfirmation,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(BaseID,SAML20_NS,false);
                PROC_TYPED_CHILD(NameID,SAML20_NS,false);
                PROC_TYPED_CHILD(EncryptedID,SAML20_NS,false);
                PROC_TYPED_CHILDREN(SubjectConfirmation,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL SubjectLocalityImpl : public virtual SubjectLocality,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Address=m_DNSName=nullptr;
            }
        public:
            virtual ~SubjectLocalityImpl() {
                XMLString::release(&m_Address);
                XMLString::release(&m_DNSName);
            }

            SubjectLocalityImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SubjectLocalityImpl(const SubjectLocalityImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setAddress(src.getAddress());
                setDNSName(src.getDNSName());
            }

            IMPL_XMLOBJECT_CLONE(SubjectLocality);
            IMPL_STRING_ATTRIB(Address);
            IMPL_STRING_ATTRIB(DNSName);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Address,ADDRESS,nullptr);
                MARSHALL_STRING_ATTRIB(DNSName,DNSNAME,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Address,ADDRESS,nullptr);
                PROC_STRING_ATTRIB(DNSName,DNSNAME,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL StatementImpl : public virtual Statement, public AnyElementImpl
        {
        public:
            virtual ~StatementImpl() {}

            StatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            StatementImpl(const StatementImpl& src) : AbstractXMLObject(src), AnyElementImpl(src) {}

            IMPL_XMLOBJECT_CLONE(Statement);
        };

        //TODO need unit test for this
        class SAML_DLLLOCAL AuthnContextDeclImpl : public virtual AuthnContextDecl, public AnyElementImpl
        {
        public:
            virtual ~AuthnContextDeclImpl() {}

            AuthnContextDeclImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            AuthnContextDeclImpl(const AuthnContextDeclImpl& src) : AbstractXMLObject(src), AnyElementImpl(src) {
            }

            IMPL_XMLOBJECT_CLONE(AuthnContextDecl);
        };

        class SAML_DLLLOCAL AuthnContextImpl : public virtual AuthnContext,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_AuthnContextClassRef=nullptr;
                m_AuthnContextDecl=nullptr;
                m_AuthnContextDeclRef=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_AuthnContextClassRef=m_children.begin();
                m_pos_AuthnContextDecl=m_pos_AuthnContextClassRef;
                ++m_pos_AuthnContextDecl;
                m_pos_AuthnContextDeclRef=m_pos_AuthnContextDecl;
                ++m_pos_AuthnContextDeclRef;
            }
        public:
            virtual ~AuthnContextImpl() {}

            AuthnContextImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AuthnContextImpl(const AuthnContextImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                if (src.getAuthnContextClassRef())
                    setAuthnContextClassRef(src.getAuthnContextClassRef()->cloneAuthnContextClassRef());
                if (src.getAuthnContextDecl())
                    setAuthnContextDecl(src.getAuthnContextDecl()->clone());
                if (src.getAuthnContextDeclRef())
                    setAuthnContextDeclRef(src.getAuthnContextDeclRef()->cloneAuthnContextDeclRef());
                VectorOf(AuthenticatingAuthority) v=getAuthenticatingAuthoritys();
                for (vector<AuthenticatingAuthority*>::const_iterator i=src.m_AuthenticatingAuthoritys.begin(); i!=src.m_AuthenticatingAuthoritys.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAuthenticatingAuthority());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(AuthnContext);
            IMPL_TYPED_CHILD(AuthnContextClassRef);
            IMPL_XMLOBJECT_CHILD(AuthnContextDecl);
            IMPL_TYPED_CHILD(AuthnContextDeclRef);
            IMPL_TYPED_CHILDREN(AuthenticatingAuthority,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(AuthnContextClassRef,SAML20_NS,false);
                PROC_XMLOBJECT_CHILD(AuthnContextDecl,SAML20_NS);
                PROC_TYPED_CHILD(AuthnContextDeclRef,SAML20_NS,false);
                PROC_TYPED_CHILDREN(AuthenticatingAuthority,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthnStatementImpl : public virtual AuthnStatement,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_AuthnInstant=nullptr;
                m_SessionIndex=nullptr;
                m_SessionNotOnOrAfter=nullptr;
                m_SubjectLocality=nullptr;
                m_AuthnContext=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_SubjectLocality=m_children.begin();
                m_pos_AuthnContext=m_pos_SubjectLocality;
                ++m_pos_AuthnContext;
            }
        public:
            virtual ~AuthnStatementImpl() {
                delete m_AuthnInstant;
                XMLString::release(&m_SessionIndex);
                delete m_SessionNotOnOrAfter;
            }

            AuthnStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AuthnStatementImpl(const AuthnStatementImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setAuthnInstant(src.getAuthnInstant());
                setSessionIndex(src.getSessionIndex());
                setSessionNotOnOrAfter(src.getSessionNotOnOrAfter());
                if (src.getSubjectLocality())
                    setSubjectLocality(src.getSubjectLocality()->cloneSubjectLocality());
                if (src.getAuthnContext())
                    setAuthnContext(src.getAuthnContext()->cloneAuthnContext());
            }

            IMPL_XMLOBJECT_CLONE(AuthnStatement);
            Statement* cloneStatement() const {
                return cloneAuthnStatement();
            }
            IMPL_DATETIME_ATTRIB(AuthnInstant,0);
            IMPL_STRING_ATTRIB(SessionIndex);
            IMPL_DATETIME_ATTRIB(SessionNotOnOrAfter,SAMLTIME_MAX);
            IMPL_TYPED_CHILD(SubjectLocality);
            IMPL_TYPED_CHILD(AuthnContext);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_DATETIME_ATTRIB(AuthnInstant,AUTHNINSTANT,nullptr);
                MARSHALL_STRING_ATTRIB(SessionIndex,SESSIONINDEX,nullptr);
                MARSHALL_DATETIME_ATTRIB(SessionNotOnOrAfter,SESSIONNOTONORAFTER,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(SubjectLocality,SAML20_NS,false);
                PROC_TYPED_CHILD(AuthnContext,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_DATETIME_ATTRIB(AuthnInstant,AUTHNINSTANT,nullptr);
                PROC_STRING_ATTRIB(SessionIndex,SESSIONINDEX,nullptr);
                PROC_DATETIME_ATTRIB(SessionNotOnOrAfter,SESSIONNOTONORAFTER,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL ActionImpl : public virtual Action,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~ActionImpl() {
                XMLString::release(&m_Namespace);
            }

            ActionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType), m_Namespace(nullptr) {
            }

            ActionImpl(const ActionImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                setNamespace(src.getNamespace());
            }

            IMPL_XMLOBJECT_CLONE(Action);
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

        class SAML_DLLLOCAL EvidenceImpl : public virtual Evidence,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~EvidenceImpl() {}

            EvidenceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            EvidenceImpl(const EvidenceImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        AssertionIDRef* ref=dynamic_cast<AssertionIDRef*>(*i);
                        if (ref) {
                            getAssertionIDRefs().push_back(ref->cloneAssertionIDRef());
                            continue;
                        }

                        AssertionURIRef* uri=dynamic_cast<AssertionURIRef*>(*i);
                        if (uri) {
                            getAssertionURIRefs().push_back(uri->cloneAssertionURIRef());
                            continue;
                        }

                        Assertion* assertion=dynamic_cast<Assertion*>(*i);
                        if (assertion) {
                            getAssertions().push_back(assertion->cloneAssertion());
                            continue;
                        }

                        EncryptedAssertion* enc=dynamic_cast<EncryptedAssertion*>(*i);
                        if (enc) {
                            getEncryptedAssertions().push_back(enc->cloneEncryptedAssertion());
                            continue;
                        }
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(Evidence);
            IMPL_TYPED_CHILDREN(AssertionIDRef,m_children.end());
            IMPL_TYPED_CHILDREN(AssertionURIRef,m_children.end());
            IMPL_TYPED_CHILDREN(Assertion,m_children.end());
            IMPL_TYPED_CHILDREN(EncryptedAssertion,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AssertionIDRef,SAML20_NS,false);
                PROC_TYPED_CHILDREN(AssertionURIRef,SAML20_NS,false);
                PROC_TYPED_CHILDREN(Assertion,SAML20_NS,false);
                PROC_TYPED_CHILDREN(EncryptedAssertion,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthzDecisionStatementImpl : public virtual AuthzDecisionStatement,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Resource=nullptr;
                m_Decision=nullptr;
                m_Evidence=nullptr;
                m_children.push_back(nullptr);
                m_pos_Evidence=m_children.begin();
            }
        public:
            virtual ~AuthzDecisionStatementImpl() {
                XMLString::release(&m_Resource);
                XMLString::release(&m_Decision);
            }

            AuthzDecisionStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AuthzDecisionStatementImpl(const AuthzDecisionStatementImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setResource(src.getResource());
                setDecision(src.getDecision());
                if (src.getEvidence())
                    setEvidence(src.getEvidence()->cloneEvidence());
                VectorOf(Action) v=getActions();
                for (vector<Action*>::const_iterator i=src.m_Actions.begin(); i!=src.m_Actions.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAction());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(AuthzDecisionStatement);
            Statement* cloneStatement() const {
                return cloneAuthzDecisionStatement();
            }
            IMPL_STRING_ATTRIB(Resource);
            IMPL_STRING_ATTRIB(Decision);
            IMPL_TYPED_CHILD(Evidence);
            IMPL_TYPED_CHILDREN(Action, m_pos_Evidence);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Resource,RESOURCE,nullptr);
                MARSHALL_STRING_ATTRIB(Decision,DECISION,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Evidence,SAML20_NS,false);
                PROC_TYPED_CHILDREN(Action,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Resource,RESOURCE,nullptr);
                PROC_STRING_ATTRIB(Decision,DECISION,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AttributeValueImpl : public virtual AttributeValue, public AnyElementImpl
        {
        public:
            virtual ~AttributeValueImpl() {}

            AttributeValueImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            AttributeValueImpl(const AttributeValueImpl& src) : AbstractXMLObject(src), AnyElementImpl(src) {
            }

            IMPL_XMLOBJECT_CLONE(AttributeValue);
        };


        class SAML_DLLLOCAL AttributeImpl : public virtual Attribute,
            public AbstractComplexElement,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Name=m_NameFormat=m_FriendlyName=nullptr;
            }
        public:
            virtual ~AttributeImpl() {
                XMLString::release(&m_Name);
                XMLString::release(&m_NameFormat);
                XMLString::release(&m_FriendlyName);
            }

            AttributeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AttributeImpl(const AttributeImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src),
                        AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                setName(src.getName());
                setNameFormat(src.getNameFormat());
                setFriendlyName(src.getFriendlyName());
                VectorOf(XMLObject) v=getAttributeValues();
                for (vector<XMLObject*>::const_iterator i=src.m_AttributeValues.begin(); i!=src.m_AttributeValues.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->clone());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(Attribute);
            IMPL_STRING_ATTRIB(Name);
            IMPL_STRING_ATTRIB(NameFormat);
            IMPL_STRING_ATTRIB(FriendlyName);
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
                }
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Name,NAME,nullptr);
                MARSHALL_STRING_ATTRIB(NameFormat,NAMEFORMAT,nullptr);
                MARSHALL_STRING_ATTRIB(FriendlyName,FRIENDLYNAME,nullptr);
                marshallExtensionAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                getAttributeValues().push_back(childXMLObject);
            }

            void processAttribute(const DOMAttr* attribute) {
                unmarshallExtensionAttribute(attribute);
            }
        };

        //TODO unit test for this
        class SAML_DLLLOCAL EncryptedAttributeImpl : public virtual EncryptedAttribute, public EncryptedElementTypeImpl
        {
        public:
            virtual ~EncryptedAttributeImpl() {}

            EncryptedAttributeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            EncryptedAttributeImpl(const EncryptedAttributeImpl& src) : AbstractXMLObject(src), EncryptedElementTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE(EncryptedAttribute);
            EncryptedElementType* cloneEncryptedElementType() const {
                return new EncryptedAttributeImpl(*this);
            }
        };

        class SAML_DLLLOCAL AttributeStatementImpl : public virtual AttributeStatement,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AttributeStatementImpl() {}

            AttributeStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            AttributeStatementImpl(const AttributeStatementImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        Attribute* attribute=dynamic_cast<Attribute*>(*i);
                        if (attribute) {
                            getAttributes().push_back(attribute->cloneAttribute());
                            continue;
                        }

                        EncryptedAttribute* enc=dynamic_cast<EncryptedAttribute*>(*i);
                        if (enc) {
                            getEncryptedAttributes().push_back(enc->cloneEncryptedAttribute());
                            continue;
                        }
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(AttributeStatement);
            Statement* cloneStatement() const {
                return cloneAttributeStatement();
            }
            IMPL_TYPED_CHILDREN(Attribute, m_children.end());
            IMPL_TYPED_CHILDREN(EncryptedAttribute, m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(Attribute,SAML20_NS,false);
                PROC_TYPED_CHILDREN(EncryptedAttribute,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AdviceImpl : public virtual Advice,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AdviceImpl() {}

            AdviceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            AdviceImpl(const AdviceImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        AssertionIDRef* ref=dynamic_cast<AssertionIDRef*>(*i);
                        if (ref) {
                            getAssertionIDRefs().push_back(ref->cloneAssertionIDRef());
                            continue;
                        }

                        AssertionURIRef* uri=dynamic_cast<AssertionURIRef*>(*i);
                        if (uri) {
                            getAssertionURIRefs().push_back(uri->cloneAssertionURIRef());
                            continue;
                        }

                        Assertion* assertion=dynamic_cast<Assertion*>(*i);
                        if (assertion) {
                            getAssertions().push_back(assertion->cloneAssertion());
                            continue;
                        }

                        EncryptedAssertion* enc=dynamic_cast<EncryptedAssertion*>(*i);
                        if (enc) {
                            getEncryptedAssertions().push_back(enc->cloneEncryptedAssertion());
                            continue;
                        }

                        getUnknownXMLObjects().push_back((*i)->clone());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(Advice);
            IMPL_TYPED_CHILDREN(AssertionIDRef,m_children.end());
            IMPL_TYPED_CHILDREN(AssertionURIRef,m_children.end());
            IMPL_TYPED_CHILDREN(Assertion,m_children.end());
            IMPL_TYPED_CHILDREN(EncryptedAssertion,m_children.end());
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AssertionIDRef,SAML20_NS,false);
                PROC_TYPED_CHILDREN(AssertionURIRef,SAML20_NS,false);
                PROC_TYPED_CHILDREN(Assertion,SAML20_NS,false);
                PROC_TYPED_CHILDREN(EncryptedAssertion,SAML20_NS,false);

                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAML20_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }

                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        //TODO unit test for this
        class SAML_DLLLOCAL EncryptedAssertionImpl : public virtual EncryptedAssertion, public EncryptedElementTypeImpl
        {
        public:
            virtual ~EncryptedAssertionImpl() {}

            EncryptedAssertionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            EncryptedAssertionImpl(const EncryptedAssertionImpl& src) : AbstractXMLObject(src), EncryptedElementTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE(EncryptedAssertion);
            EncryptedElementType* cloneEncryptedElementType() const {
                return new EncryptedAssertionImpl(*this);
            }
        };

        class SAML_DLLLOCAL AssertionImpl : public virtual Assertion,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ID=nullptr;
                m_Version=nullptr;
                m_IssueInstant=nullptr;
                m_Issuer=nullptr;
                m_Signature=nullptr;
                m_Subject=nullptr;
                m_Conditions=nullptr;
                m_Advice=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_Issuer=m_children.begin();
                m_pos_Signature=m_pos_Issuer;
                ++m_pos_Signature;
                m_pos_Subject=m_pos_Signature;
                ++m_pos_Subject;
                m_pos_Conditions=m_pos_Subject;
                ++m_pos_Conditions;
                m_pos_Advice=m_pos_Conditions;
                ++m_pos_Advice;
            }
        public:
            virtual ~AssertionImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_Version);
                delete m_IssueInstant;
            }

            AssertionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AssertionImpl(const AssertionImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setVersion(src.getVersion());
                setID(src.getID());
                setIssueInstant(src.getIssueInstant());
                if (src.getIssuer())
                    setIssuer(src.getIssuer()->cloneIssuer());
                if (src.getSignature())
                    setSignature(src.getSignature()->cloneSignature());
                if (src.getSubject())
                    setSubject(src.getSubject()->cloneSubject());
                if (src.getConditions())
                    setConditions(src.getConditions()->cloneConditions());
                if (src.getAdvice())
                    setAdvice(src.getAdvice()->cloneAdvice());
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        AuthnStatement* authst=dynamic_cast<AuthnStatement*>(*i);
                        if (authst) {
                            getAuthnStatements().push_back(authst->cloneAuthnStatement());
                            continue;
                        }

                        AttributeStatement* attst=dynamic_cast<AttributeStatement*>(*i);
                        if (attst) {
                            getAttributeStatements().push_back(attst->cloneAttributeStatement());
                            continue;
                        }

                        AuthzDecisionStatement* authzst=dynamic_cast<AuthzDecisionStatement*>(*i);
                        if (authzst) {
                            getAuthzDecisionStatements().push_back(authzst->cloneAuthzDecisionStatement());
                            continue;
                        }

                        Statement* st=dynamic_cast<Statement*>(*i);
                        if (st) {
                            getStatements().push_back(st->cloneStatement());
                            continue;
                        }
                    }
                }
            }

            //IMPL_TYPED_CHILD(Signature);
            // Need customized setter.
        protected:
            Signature* m_Signature;
            list<XMLObject*>::iterator m_pos_Signature;
        public:
            Signature* getSignature() const {
                return m_Signature;
            }

            void setSignature(Signature* sig) {
                prepareForAssignment(m_Signature,sig);
                *m_pos_Signature=m_Signature=sig;
                // Sync content reference back up.
                if (m_Signature)
                    m_Signature->setContentReference(new opensaml::ContentReference(*this));
            }

            IMPL_XMLOBJECT_CLONE(Assertion);
            IMPL_STRING_ATTRIB(Version);
            IMPL_ID_ATTRIB_EX(ID,ID,nullptr);
            IMPL_DATETIME_ATTRIB(IssueInstant,0);
            IMPL_TYPED_CHILD(Issuer);
            IMPL_TYPED_CHILD(Subject);
            IMPL_TYPED_CHILD(Conditions);
            IMPL_TYPED_CHILD(Advice);
            IMPL_TYPED_CHILDREN(Statement, m_children.end());
            IMPL_TYPED_CHILDREN(AuthnStatement, m_children.end());
            IMPL_TYPED_CHILDREN(AttributeStatement, m_children.end());
            IMPL_TYPED_CHILDREN(AuthzDecisionStatement, m_children.end());

        protected:
            void prepareForMarshalling() const {
                if (m_Signature)
                    declareNonVisibleNamespaces();
            }

            void marshallAttributes(DOMElement* domElement) const {
                if (!m_Version)
                    const_cast<AssertionImpl*>(this)->m_Version=XMLString::transcode("2.0");
                MARSHALL_STRING_ATTRIB(Version,VER,nullptr);
                if (!m_ID)
                    const_cast<AssertionImpl*>(this)->m_ID=SAMLConfig::getConfig().generateIdentifier();
                MARSHALL_ID_ATTRIB(ID,ID,nullptr);
                if (!m_IssueInstant) {
                    const_cast<AssertionImpl*>(this)->m_IssueInstantEpoch=time(nullptr);
                    const_cast<AssertionImpl*>(this)->m_IssueInstant=new DateTime(m_IssueInstantEpoch);
                }
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Issuer,SAML20_NS,false);
                PROC_TYPED_CHILD(Signature,XMLSIG_NS,false);
                PROC_TYPED_CHILD(Subject,SAML20_NS,false);
                PROC_TYPED_CHILD(Conditions,SAML20_NS,false);
                PROC_TYPED_CHILD(Advice,SAML20_NS,false);
                PROC_TYPED_CHILDREN(AuthnStatement,SAML20_NS,false);
                PROC_TYPED_CHILDREN(AttributeStatement,SAML20_NS,false);
                PROC_TYPED_CHILDREN(AuthzDecisionStatement,SAML20_NS,false);
                PROC_TYPED_CHILDREN(Statement,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Version,VER,nullptr);
                PROC_ID_ATTRIB(ID,ID,nullptr);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

// Builder Implementations

IMPL_XMLOBJECTBUILDER(Action);
IMPL_XMLOBJECTBUILDER(Advice);
IMPL_XMLOBJECTBUILDER(Assertion);
IMPL_XMLOBJECTBUILDER(AssertionIDRef);
IMPL_XMLOBJECTBUILDER(AssertionURIRef);
IMPL_XMLOBJECTBUILDER(Attribute);
IMPL_XMLOBJECTBUILDER(AttributeStatement);
IMPL_XMLOBJECTBUILDER(AttributeValue);
IMPL_XMLOBJECTBUILDER(Audience);
IMPL_XMLOBJECTBUILDER(AudienceRestriction);
IMPL_XMLOBJECTBUILDER(AuthenticatingAuthority);
IMPL_XMLOBJECTBUILDER(AuthnContext);
IMPL_XMLOBJECTBUILDER(AuthnContextClassRef);
IMPL_XMLOBJECTBUILDER(AuthnContextDecl);
IMPL_XMLOBJECTBUILDER(AuthnContextDeclRef);
IMPL_XMLOBJECTBUILDER(AuthnStatement);
IMPL_XMLOBJECTBUILDER(AuthzDecisionStatement);
IMPL_XMLOBJECTBUILDER(Condition);
IMPL_XMLOBJECTBUILDER(Conditions);
IMPL_XMLOBJECTBUILDER(Delegate);
IMPL_XMLOBJECTBUILDER(DelegationRestrictionType);
IMPL_XMLOBJECTBUILDER(EncryptedAssertion);
IMPL_XMLOBJECTBUILDER(EncryptedAttribute);
IMPL_XMLOBJECTBUILDER(EncryptedID);
IMPL_XMLOBJECTBUILDER(Evidence);
IMPL_XMLOBJECTBUILDER(Issuer);
IMPL_XMLOBJECTBUILDER(KeyInfoConfirmationDataType);
IMPL_XMLOBJECTBUILDER(NameID);
IMPL_XMLOBJECTBUILDER(NameIDType);
IMPL_XMLOBJECTBUILDER(OneTimeUse);
IMPL_XMLOBJECTBUILDER(ProxyRestriction);
IMPL_XMLOBJECTBUILDER(Statement);
IMPL_XMLOBJECTBUILDER(Subject);
IMPL_XMLOBJECTBUILDER(SubjectConfirmation);
IMPL_XMLOBJECTBUILDER(SubjectConfirmationData);
IMPL_XMLOBJECTBUILDER(SubjectLocality);

// Unicode literals
const XMLCh Action::LOCAL_NAME[] =                  UNICODE_LITERAL_6(A,c,t,i,o,n);
const XMLCh Action::TYPE_NAME[] =                   UNICODE_LITERAL_10(A,c,t,i,o,n,T,y,p,e);
const XMLCh Action::NAMESPACE_ATTRIB_NAME[] =       UNICODE_LITERAL_9(N,a,m,e,s,p,a,c,e);
const XMLCh Advice::LOCAL_NAME[] =                  UNICODE_LITERAL_6(A,d,v,i,c,e);
const XMLCh Advice::TYPE_NAME[] =                   UNICODE_LITERAL_10(A,d,v,i,c,e,T,y,p,e);
const XMLCh Assertion::LOCAL_NAME[] =               UNICODE_LITERAL_9(A,s,s,e,r,t,i,o,n);
const XMLCh Assertion::TYPE_NAME[] =                UNICODE_LITERAL_13(A,s,s,e,r,t,i,o,n,T,y,p,e);
const XMLCh Assertion::VER_ATTRIB_NAME[] =          UNICODE_LITERAL_7(V,e,r,s,i,o,n);
const XMLCh Assertion::ID_ATTRIB_NAME[] =           UNICODE_LITERAL_2(I,D);
const XMLCh Assertion::ISSUEINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_12(I,s,s,u,e,I,n,s,t,a,n,t);
const XMLCh AssertionIDRef::LOCAL_NAME[] =          UNICODE_LITERAL_14(A,s,s,e,r,t,i,o,n,I,D,R,e,f);
const XMLCh AssertionURIRef::LOCAL_NAME[] =         UNICODE_LITERAL_15(A,s,s,e,r,t,i,o,n,U,R,I,R,e,f);
const XMLCh Attribute::LOCAL_NAME[] =               UNICODE_LITERAL_9(A,t,t,r,i,b,u,t,e);
const XMLCh Attribute::TYPE_NAME[] =                UNICODE_LITERAL_13(A,t,t,r,i,b,u,t,e,T,y,p,e);
const XMLCh Attribute::NAME_ATTRIB_NAME[] =         UNICODE_LITERAL_4(N,a,m,e);
const XMLCh Attribute::NAMEFORMAT_ATTRIB_NAME[] =   UNICODE_LITERAL_10(N,a,m,e,F,o,r,m,a,t);
const XMLCh Attribute::FRIENDLYNAME_ATTRIB_NAME[] = UNICODE_LITERAL_12(F,r,i,e,n,d,l,y,N,a,m,e);
const XMLCh AttributeStatement::LOCAL_NAME[] =      UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,S,t,a,t,e,m,e,n,t);
const XMLCh AttributeStatement::TYPE_NAME[] =       UNICODE_LITERAL_22(A,t,t,r,i,b,u,t,e,S,t,a,t,e,m,e,n,t,T,y,p,e);
const XMLCh AttributeValue::LOCAL_NAME[] =          UNICODE_LITERAL_14(A,t,t,r,i,b,u,t,e,V,a,l,u,e);
const XMLCh Audience::LOCAL_NAME[] =                UNICODE_LITERAL_8(A,u,d,i,e,n,c,e);
const XMLCh AudienceRestriction::LOCAL_NAME[] =     UNICODE_LITERAL_19(A,u,d,i,e,n,c,e,R,e,s,t,r,i,c,t,i,o,n);
const XMLCh AudienceRestriction::TYPE_NAME[] =      UNICODE_LITERAL_23(A,u,d,i,e,n,c,e,R,e,s,t,r,i,c,t,i,o,n,T,y,p,e);
const XMLCh AuthenticatingAuthority::LOCAL_NAME[] = UNICODE_LITERAL_23(A,u,t,h,e,n,t,i,c,a,t,i,n,g,A,u,t,h,o,r,i,t,y);
const XMLCh AuthnContext::LOCAL_NAME[] =            UNICODE_LITERAL_12(A,u,t,h,n,C,o,n,t,e,x,t);
const XMLCh AuthnContext::TYPE_NAME[] =             UNICODE_LITERAL_16(A,u,t,h,n,C,o,n,t,e,x,t,T,y,p,e);
const XMLCh AuthnContextClassRef::LOCAL_NAME[] =    UNICODE_LITERAL_20(A,u,t,h,n,C,o,n,t,e,x,t,C,l,a,s,s,R,e,f);
const XMLCh AuthnContextDecl::LOCAL_NAME[] =        UNICODE_LITERAL_16(A,u,t,h,n,C,o,n,t,e,x,t,D,e,c,l);
const XMLCh AuthnContextDeclRef::LOCAL_NAME[] =     UNICODE_LITERAL_19(A,u,t,h,n,C,o,n,t,e,x,t,D,e,c,l,R,e,f);
const XMLCh AuthnStatement::LOCAL_NAME[] =          UNICODE_LITERAL_14(A,u,t,h,n,S,t,a,t,e,m,e,n,t);
const XMLCh AuthnStatement::TYPE_NAME[] =           UNICODE_LITERAL_18(A,u,t,h,n,S,t,a,t,e,m,e,n,t,T,y,p,e);
const XMLCh AuthnStatement::AUTHNINSTANT_ATTRIB_NAME[] =    UNICODE_LITERAL_12(A,u,t,h,n,I,n,s,t,a,n,t);
const XMLCh AuthnStatement::SESSIONINDEX_ATTRIB_NAME[] =    UNICODE_LITERAL_12(S,e,s,s,i,o,n,I,n,d,e,x);
const XMLCh AuthnStatement::SESSIONNOTONORAFTER_ATTRIB_NAME[] = UNICODE_LITERAL_19(S,e,s,s,i,o,n,N,o,t,O,n,O,r,A,f,t,e,r);
const XMLCh AuthzDecisionStatement::LOCAL_NAME[] =  UNICODE_LITERAL_22(A,u,t,h,z,D,e,c,i,s,i,o,n,S,t,a,t,e,m,e,n,t);
const XMLCh AuthzDecisionStatement::TYPE_NAME[] =   UNICODE_LITERAL_26(A,u,t,h,z,D,e,c,i,s,i,o,n,S,t,a,t,e,m,e,n,t,T,y,p,e);
const XMLCh AuthzDecisionStatement::RESOURCE_ATTRIB_NAME[] =    UNICODE_LITERAL_8(R,e,s,o,u,r,c,e);
const XMLCh AuthzDecisionStatement::DECISION_ATTRIB_NAME[] =    UNICODE_LITERAL_8(D,e,c,i,s,i,o,n);
const XMLCh AuthzDecisionStatement::DECISION_PERMIT[] = UNICODE_LITERAL_6(P,e,r,m,i,t);
const XMLCh AuthzDecisionStatement::DECISION_DENY[] =   UNICODE_LITERAL_4(D,e,n,y);
const XMLCh AuthzDecisionStatement::DECISION_INDETERMINATE[] =  UNICODE_LITERAL_13(I,n,d,e,t,e,r,m,i,n,a,t,e);
const XMLCh BaseID::LOCAL_NAME[] =                  UNICODE_LITERAL_6(B,a,s,e,I,D);
const XMLCh BaseID::NAMEQUALIFIER_ATTRIB_NAME[] =   UNICODE_LITERAL_13(N,a,m,e,Q,u,a,l,i,f,i,e,r);
const XMLCh BaseID::SPNAMEQUALIFIER_ATTRIB_NAME[] = UNICODE_LITERAL_15(S,P,N,a,m,e,Q,u,a,l,i,f,i,e,r);
const XMLCh Condition::LOCAL_NAME[] =               UNICODE_LITERAL_9(C,o,n,d,i,t,i,o,n);
const XMLCh Conditions::LOCAL_NAME[] =              UNICODE_LITERAL_10(C,o,n,d,i,t,i,o,n,s);
const XMLCh Conditions::TYPE_NAME[] =               UNICODE_LITERAL_14(C,o,n,d,i,t,i,o,n,s,T,y,p,e);
const XMLCh Conditions::NOTBEFORE_ATTRIB_NAME[] =   UNICODE_LITERAL_9(N,o,t,B,e,f,o,r,e);
const XMLCh Conditions::NOTONORAFTER_ATTRIB_NAME[] =UNICODE_LITERAL_12(N,o,t,O,n,O,r,A,f,t,e,r);
const XMLCh Delegate::LOCAL_NAME[] =                UNICODE_LITERAL_8(D,e,l,e,g,a,t,e);
const XMLCh Delegate::TYPE_NAME[] =                 UNICODE_LITERAL_12(D,e,l,e,g,a,t,e,T,y,p,e);
const XMLCh Delegate::CONFIRMATIONMETHOD_ATTRIB_NAME[] = UNICODE_LITERAL_18(C,o,n,f,i,r,m,a,t,i,o,n,M,e,t,h,o,d);
const XMLCh Delegate::DELEGATIONINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_17(D,e,l,e,g,a,t,i,o,n,I,n,s,t,a,n,t);
const XMLCh DelegationRestrictionType::LOCAL_NAME[] = UNICODE_LITERAL_9(C,o,n,d,i,t,i,o,n);
const XMLCh DelegationRestrictionType::TYPE_NAME[] =UNICODE_LITERAL_25(D,e,l,e,g,a,t,i,o,n,R,e,s,t,r,i,c,t,i,o,n,T,y,p,e);
const XMLCh EncryptedAssertion::LOCAL_NAME[] =      UNICODE_LITERAL_18(E,n,c,r,y,p,t,e,d,A,s,s,e,r,t,i,o,n);
const XMLCh EncryptedAttribute::LOCAL_NAME[] =      UNICODE_LITERAL_18(E,n,c,r,y,p,t,e,d,A,t,t,r,i,b,u,t,e);
const XMLCh EncryptedElementType::LOCAL_NAME[] =    {chNull};
const XMLCh EncryptedElementType::TYPE_NAME[] =     UNICODE_LITERAL_20(E,n,c,r,y,p,t,e,d,E,l,e,m,e,n,t,T,y,p,e);
const XMLCh EncryptedID::LOCAL_NAME[] =             UNICODE_LITERAL_11(E,n,c,r,y,p,t,e,d,I,D);
const XMLCh Evidence::LOCAL_NAME[] =                UNICODE_LITERAL_8(E,v,i,d,e,n,c,e);
const XMLCh Evidence::TYPE_NAME[] =                 UNICODE_LITERAL_12(E,v,i,d,e,n,c,e,T,y,p,e);
const XMLCh Issuer::LOCAL_NAME[] =                  UNICODE_LITERAL_6(I,s,s,u,e,r);
const XMLCh KeyInfoConfirmationDataType::LOCAL_NAME[] = UNICODE_LITERAL_23(S,u,b,j,e,c,t,C,o,n,f,i,r,m,a,t,i,o,n,D,a,t,a);
const XMLCh KeyInfoConfirmationDataType::TYPE_NAME[] = UNICODE_LITERAL_27(K,e,y,I,n,f,o,C,o,n,f,i,r,m,a,t,i,o,n,D,a,t,a,T,y,p,e);
const XMLCh NameID::LOCAL_NAME[] =                  UNICODE_LITERAL_6(N,a,m,e,I,D);
const XMLCh NameIDType::LOCAL_NAME[] =              {chNull};
const XMLCh NameIDType::TYPE_NAME[] =               UNICODE_LITERAL_10(N,a,m,e,I,D,T,y,p,e);
const XMLCh NameIDType::NAMEQUALIFIER_ATTRIB_NAME[] =   UNICODE_LITERAL_13(N,a,m,e,Q,u,a,l,i,f,i,e,r);
const XMLCh NameIDType::SPNAMEQUALIFIER_ATTRIB_NAME[] = UNICODE_LITERAL_15(S,P,N,a,m,e,Q,u,a,l,i,f,i,e,r);
const XMLCh NameIDType::FORMAT_ATTRIB_NAME[] =      UNICODE_LITERAL_6(F,o,r,m,a,t);
const XMLCh NameIDType::SPPROVIDEDID_ATTRIB_NAME[] =    UNICODE_LITERAL_12(S,P,P,r,o,v,i,d,e,d,I,D);
const XMLCh OneTimeUse::LOCAL_NAME[] =              UNICODE_LITERAL_10(O,n,e,T,i,m,e,U,s,e);
const XMLCh OneTimeUse::TYPE_NAME[] =               UNICODE_LITERAL_14(O,n,e,T,i,m,e,U,s,e,T,y,p,e);
const XMLCh ProxyRestriction::LOCAL_NAME[] =        UNICODE_LITERAL_16(P,r,o,x,y,R,e,s,t,r,i,c,t,i,o,n);
const XMLCh ProxyRestriction::TYPE_NAME[] =         UNICODE_LITERAL_20(P,r,o,x,y,R,e,s,t,r,i,c,t,i,o,n,T,y,p,e);
const XMLCh ProxyRestriction::COUNT_ATTRIB_NAME[] = UNICODE_LITERAL_5(C,o,u,n,t);
const XMLCh Statement::LOCAL_NAME[] =               UNICODE_LITERAL_9(S,t,a,t,e,m,e,n,t);
const XMLCh Subject::LOCAL_NAME[] =                 UNICODE_LITERAL_7(S,u,b,j,e,c,t);
const XMLCh Subject::TYPE_NAME[] =                  UNICODE_LITERAL_11(S,u,b,j,e,c,t,T,y,p,e);
const XMLCh SubjectConfirmation::LOCAL_NAME[] =     UNICODE_LITERAL_19(S,u,b,j,e,c,t,C,o,n,f,i,r,m,a,t,i,o,n);
const XMLCh SubjectConfirmation::TYPE_NAME[] =      UNICODE_LITERAL_23(S,u,b,j,e,c,t,C,o,n,f,i,r,m,a,t,i,o,n,T,y,p,e);
const XMLCh SubjectConfirmation::METHOD_ATTRIB_NAME[] = UNICODE_LITERAL_6(M,e,t,h,o,d);
const XMLCh SubjectConfirmationData::LOCAL_NAME[] = UNICODE_LITERAL_23(S,u,b,j,e,c,t,C,o,n,f,i,r,m,a,t,i,o,n,D,a,t,a);
const XMLCh SubjectConfirmationDataType::NOTBEFORE_ATTRIB_NAME[] =      UNICODE_LITERAL_9(N,o,t,B,e,f,o,r,e);
const XMLCh SubjectConfirmationDataType::NOTONORAFTER_ATTRIB_NAME[] =   UNICODE_LITERAL_12(N,o,t,O,n,O,r,A,f,t,e,r);
const XMLCh SubjectConfirmationDataType::INRESPONSETO_ATTRIB_NAME[] =   UNICODE_LITERAL_12(I,n,R,e,s,p,o,n,s,e,T,o);
const XMLCh SubjectConfirmationDataType::RECIPIENT_ATTRIB_NAME[] =      UNICODE_LITERAL_9(R,e,c,i,p,i,e,n,t);
const XMLCh SubjectConfirmationDataType::ADDRESS_ATTRIB_NAME[] =        UNICODE_LITERAL_7(A,d,d,r,e,s,s);
const XMLCh SubjectLocality::LOCAL_NAME[] =         UNICODE_LITERAL_15(S,u,b,j,e,c,t,L,o,c,a,l,i,t,y);
const XMLCh SubjectLocality::TYPE_NAME[] =          UNICODE_LITERAL_19(S,u,b,j,e,c,t,L,o,c,a,l,i,t,y,T,y,p,e);
const XMLCh SubjectLocality::ADDRESS_ATTRIB_NAME[] =UNICODE_LITERAL_7(A,d,d,r,e,s,s);
const XMLCh SubjectLocality::DNSNAME_ATTRIB_NAME[] =UNICODE_LITERAL_7(D,N,S,N,a,m,e);

const XMLCh NameIDType::UNSPECIFIED[] = // urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_u, chLatin_n, chLatin_s, chLatin_p, chLatin_e, chLatin_c, chLatin_i, chLatin_f, chLatin_i, chLatin_e, chLatin_d, chNull
};

const XMLCh NameIDType::EMAIL[] = // urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_e, chLatin_m, chLatin_a, chLatin_i, chLatin_l, chLatin_A, chLatin_d, chLatin_d, chLatin_r, chLatin_e, chLatin_s, chLatin_s, chNull
};

const XMLCh NameIDType::X509_SUBJECT[] = // urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_X, chDigit_5, chDigit_0, chDigit_9, chLatin_S, chLatin_u, chLatin_b, chLatin_j, chLatin_e, chLatin_c, chLatin_t,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull
};

const XMLCh NameIDType::WIN_DOMAIN_QUALIFIED[] = // urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_W, chLatin_i, chLatin_n, chLatin_d, chLatin_o, chLatin_w, chLatin_s,
  chLatin_D, chLatin_o, chLatin_m, chLatin_a, chLatin_i, chLatin_n,
  chLatin_Q, chLatin_u, chLatin_a, chLatin_l, chLatin_i, chLatin_f, chLatin_i, chLatin_e, chLatin_d,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull
};

const XMLCh NameIDType::KERBEROS[] = // urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_k, chLatin_e, chLatin_r, chLatin_b, chLatin_e, chLatin_r, chLatin_o, chLatin_s, chNull
};

const XMLCh NameIDType::ENTITY[] = // urn:oasis:names:tc:SAML:2.0:nameid-format:entity
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_t, chLatin_y, chNull
};

const XMLCh NameIDType::PERSISTENT[] = // urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_p, chLatin_e, chLatin_r, chLatin_s, chLatin_i, chLatin_s, chLatin_t, chLatin_e, chLatin_n, chLatin_t, chNull
};

const XMLCh NameIDType::TRANSIENT[] = // urn:oasis:names:tc:SAML:2.0:nameid-format:transient
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_t, chLatin_r, chLatin_a, chLatin_n, chLatin_s, chLatin_i, chLatin_e, chLatin_n, chLatin_t, chNull
};

const XMLCh SubjectConfirmation::BEARER[] = // urn:oasis:names:tc:SAML:2.0:cm:bearer
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_c, chLatin_m, chColon, chLatin_b, chLatin_e, chLatin_a, chLatin_r, chLatin_e, chLatin_r, chNull
};

const XMLCh SubjectConfirmation::HOLDER_KEY[] = // urn:oasis:names:tc:SAML:2.0:cm:holder-of-key
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_c, chLatin_m, chColon, chLatin_h, chLatin_o, chLatin_l, chLatin_d, chLatin_e, chLatin_r, chDash,
      chLatin_o, chLatin_f, chDash, chLatin_k, chLatin_e, chLatin_y, chNull
};

const XMLCh SubjectConfirmation::SENDER_VOUCHES[] = // urn:oasis:names:tc:SAML:2.0:cm:sender-vouches
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_c, chLatin_m, chColon, chLatin_s, chLatin_e, chLatin_n, chLatin_d, chLatin_e, chLatin_r, chDash,
      chLatin_v, chLatin_o, chLatin_u, chLatin_c, chLatin_h, chLatin_e, chLatin_s, chNull
};

const XMLCh Action::RWEDC_ACTION_NAMESPACE[] = // urn:oasis:names:tc:SAML:1.0:action:rwedc
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_c, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chColon,
  chLatin_r, chLatin_w, chLatin_e, chLatin_d, chLatin_c, chNull
};

const XMLCh Action::RWEDC_NEG_ACTION_NAMESPACE[] = // urn:oasis:names:tc:SAML:1.0:action:rwedc-negation
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_c, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chColon,
  chLatin_r, chLatin_w, chLatin_e, chLatin_d, chLatin_c, chDash,
  chLatin_n, chLatin_e, chLatin_g, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh Action::GHPP_ACTION_NAMESPACE[] = // urn:oasis:names:tc:SAML:1.0:action:ghpp
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_c, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chColon,
  chLatin_g, chLatin_h, chLatin_p, chLatin_p, chNull
};

const XMLCh Action::UNIX_ACTION_NAMESPACE[] = // urn:oasis:names:tc:SAML:1.0:action:unix
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_c, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chColon,
  chLatin_u, chLatin_n, chLatin_i, chLatin_x, chNull
};

const XMLCh Attribute::UNSPECIFIED[] = // urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_n, chLatin_a, chLatin_m, chLatin_e, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_u, chLatin_n, chLatin_s, chLatin_p, chLatin_e, chLatin_c, chLatin_i, chLatin_f, chLatin_i, chLatin_e, chLatin_d, chNull
};

const XMLCh Attribute::URI_REFERENCE[] = // urn:oasis:names:tc:SAML:2.0:attrname-format:uri
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_n, chLatin_a, chLatin_m, chLatin_e, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_u, chLatin_r, chLatin_i, chNull
};

const XMLCh Attribute::BASIC[] = // urn:oasis:names:tc:SAML:2.0:attrname-format:basic
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_n, chLatin_a, chLatin_m, chLatin_e, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_b, chLatin_a, chLatin_s, chLatin_i, chLatin_c, chNull
};
