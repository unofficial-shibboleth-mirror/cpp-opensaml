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
 * Assertions20Impl.cpp
 * 
 * Implementation classes for SAML 2.0 Assertions schema
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/encryption/EncryptedKeyResolver.h"
#include "saml2/core/Assertions.h"

#include <xmltooling/AbstractChildlessElement.h>
#include <xmltooling/AbstractComplexElement.h>
#include <xmltooling/AbstractElementProxy.h>
#include <xmltooling/AbstractSimpleElement.h>
#include <xmltooling/encryption/Decrypter.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>
#include <xmltooling/util/XMLHelper.h>

#include <ctime>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmlencryption;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

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
            public AbstractChildlessElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Format=m_SPProvidedID=m_NameQualifier=m_SPNameQualifier=NULL;
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
    
            NameIDTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
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
            IMPL_XMLOBJECT_CONTENT;
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER,NULL);
                MARSHALL_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER,NULL);
                MARSHALL_STRING_ATTRIB(Format,FORMAT,NULL);
                MARSHALL_STRING_ATTRIB(SPProvidedID,SPPROVIDEDID,NULL);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER,NULL);
                PROC_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER,NULL);
                PROC_STRING_ATTRIB(Format,FORMAT,NULL);
                PROC_STRING_ATTRIB(SPProvidedID,SPPROVIDEDID,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL NameIDImpl : public virtual NameID, public NameIDTypeImpl
        {
        public:
            virtual ~NameIDImpl() {}
    
            NameIDImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
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
    
            IssuerImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}
                
            IssuerImpl(const IssuerImpl& src) : AbstractXMLObject(src), NameIDTypeImpl(src) {}
            
            IMPL_XMLOBJECT_CLONE(Issuer);
            NameIDType* cloneNameIDType() const {
                return new IssuerImpl(*this);
            }
        };

        class SAML_DLLLOCAL EncryptedElementTypeImpl : public virtual EncryptedElementType,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_EncryptedData=NULL;
                m_children.push_back(NULL);
                m_pos_EncryptedData=m_children.begin();
            }
            
        protected:
            EncryptedElementTypeImpl() {
                init();
            }
            
        public:
            virtual ~EncryptedElementTypeImpl() {}
    
            EncryptedElementTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            EncryptedElementTypeImpl(const EncryptedElementTypeImpl& src)
                    : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
    
            XMLObject* decrypt(KeyResolver* KEKresolver, const XMLCh* recipient) const
            {
                if (!m_EncryptedData)
                    throw DecryptionException("No encrypted data present.");
                Decrypter decrypter(KEKresolver, new EncryptedKeyResolver(*this, recipient));
                DOMDocumentFragment* frag = decrypter.decryptData(m_EncryptedData);
                if (frag->hasChildNodes() && frag->getFirstChild()==frag->getLastChild()) {
                    DOMNode* plaintext=frag->getFirstChild();
                    if (plaintext->getNodeType()==DOMNode::ELEMENT_NODE) {
                        auto_ptr<XMLObject> ret(XMLObjectBuilder::buildOneFromElement(static_cast<DOMElement*>(plaintext)));
                        ret->releaseThisAndChildrenDOM();
                        return ret.release();
                    }
                }
                frag->release();
                throw DecryptionException("Decryption did not result in a single element.");
            }
        
            IMPL_XMLOBJECT_CLONE(EncryptedElementType);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption);
            IMPL_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption,XMLConstants::XMLENC_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption,XMLConstants::XMLENC_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL EncryptedIDImpl : public virtual EncryptedID, public EncryptedElementTypeImpl
        {
        public:
            virtual ~EncryptedIDImpl() {}
    
            EncryptedIDImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}
                
            EncryptedIDImpl(const EncryptedIDImpl& src) : AbstractXMLObject(src), EncryptedElementTypeImpl(src) {}
            
            IMPL_XMLOBJECT_CLONE(EncryptedID);
            EncryptedElementType* cloneEncryptedElementType() const {
                return new EncryptedIDImpl(*this);
            }
        };

        class SAML_DLLLOCAL AudienceRestrictionImpl : public virtual AudienceRestriction,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AudienceRestrictionImpl() {}
    
            AudienceRestrictionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            AudienceRestrictionImpl(const AudienceRestrictionImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                PROC_TYPED_CHILDREN(Audience,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL OneTimeUseImpl : public virtual OneTimeUse,
            public AbstractChildlessElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~OneTimeUseImpl() {}
    
            OneTimeUseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            OneTimeUseImpl(const OneTimeUseImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
    
            ProxyRestrictionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                m_Count=NULL;
            }
                
            ProxyRestrictionImpl(const ProxyRestrictionImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                MARSHALL_INTEGER_ATTRIB(Count,COUNT,NULL);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(Audience,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_INTEGER_ATTRIB(Count,COUNT,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };


        class SAML_DLLLOCAL ConditionsImpl : public virtual Conditions,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_NotBefore=m_NotOnOrAfter=NULL;
            }
        public:
            virtual ~ConditionsImpl() {
                delete m_NotBefore;
                delete m_NotOnOrAfter;
            }
    
            ConditionsImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            ConditionsImpl(const ConditionsImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                MARSHALL_DATETIME_ATTRIB(NotBefore,NOTBEFORE,NULL);
                MARSHALL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,NULL);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AudienceRestriction,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(OneTimeUse,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(ProxyRestriction,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(Condition,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_DATETIME_ATTRIB(NotBefore,NOTBEFORE,NULL);
                PROC_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL SubjectConfirmationDataImpl : public virtual SubjectConfirmationData, public AnyElementImpl
        {
            void init() {
                m_NotBefore=m_NotOnOrAfter=NULL;
                m_Recipient=m_InResponseTo=m_Address=NULL;
            }
        public:
            virtual ~SubjectConfirmationDataImpl() {
                delete m_NotBefore;
                delete m_NotOnOrAfter;
                XMLString::release(&m_Recipient);
                XMLString::release(&m_InResponseTo);
                XMLString::release(&m_Address);
            }
    
            SubjectConfirmationDataImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            SubjectConfirmationDataImpl(const SubjectConfirmationDataImpl& src) : AnyElementImpl(src) {
                init();
                setNotBefore(src.getNotBefore());
                setNotOnOrAfter(src.getNotOnOrAfter());
                setRecipient(src.getRecipient());
                setInResponseTo(src.getInResponseTo());
                setAddress(src.getAddress());
            }
            
            IMPL_XMLOBJECT_CLONE(SubjectConfirmationData);
            IMPL_DATETIME_ATTRIB(NotBefore,0);
            IMPL_DATETIME_ATTRIB(NotOnOrAfter,SAMLTIME_MAX);
            IMPL_STRING_ATTRIB(Recipient);
            IMPL_STRING_ATTRIB(InResponseTo);
            IMPL_STRING_ATTRIB(Address);
            
        public:
            void setAttribute(QName& qualifiedName, const XMLCh* value) {
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
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_DATETIME_ATTRIB(NotBefore,NOTBEFORE,NULL);
                MARSHALL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,NULL);
                MARSHALL_STRING_ATTRIB(Recipient,RECIPIENT,NULL);
                MARSHALL_STRING_ATTRIB(InResponseTo,INRESPONSETO,NULL);
                MARSHALL_STRING_ATTRIB(Address,ADDRESS,NULL);
                AnyElementImpl::marshallAttributes(domElement);
            }
            
            // The processAttributes hook is handled by AnyElementImpl
        };

        class SAML_DLLLOCAL KeyInfoConfirmationDataTypeImpl : public virtual KeyInfoConfirmationDataType,
                public AbstractComplexElement,
                public AbstractAttributeExtensibleXMLObject,
                public AbstractDOMCachingXMLObject,
                public AbstractXMLObjectMarshaller,
                public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_NotBefore=m_NotOnOrAfter=NULL;
                m_Recipient=m_InResponseTo=m_Address=NULL;
            }
        public:
            virtual ~KeyInfoConfirmationDataTypeImpl() {
                delete m_NotBefore;
                delete m_NotOnOrAfter;
                XMLString::release(&m_Recipient);
                XMLString::release(&m_InResponseTo);
                XMLString::release(&m_Address);
            }
    
            KeyInfoConfirmationDataTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            KeyInfoConfirmationDataTypeImpl(const KeyInfoConfirmationDataTypeImpl& src)
                    : AbstractXMLObject(src), AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                setNotBefore(src.getNotBefore());
                setNotOnOrAfter(src.getNotOnOrAfter());
                setRecipient(src.getRecipient());
                setInResponseTo(src.getInResponseTo());
                setAddress(src.getAddress());
                VectorOf(KeyInfo) v=getKeyInfos();
                for (vector<KeyInfo*>::const_iterator i=src.m_KeyInfos.begin(); i!=src.m_KeyInfos.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneKeyInfo());
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(KeyInfoConfirmationDataType);
            IMPL_DATETIME_ATTRIB(NotBefore,0);
            IMPL_DATETIME_ATTRIB(NotOnOrAfter,SAMLTIME_MAX);
            IMPL_STRING_ATTRIB(Recipient);
            IMPL_STRING_ATTRIB(InResponseTo);
            IMPL_STRING_ATTRIB(Address);
            IMPL_TYPED_CHILDREN(KeyInfo,m_children.end());
            
        public:
            void setAttribute(QName& qualifiedName, const XMLCh* value) {
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
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_DATETIME_ATTRIB(NotBefore,NOTBEFORE,NULL);
                MARSHALL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,NULL);
                MARSHALL_STRING_ATTRIB(Recipient,RECIPIENT,NULL);
                MARSHALL_STRING_ATTRIB(InResponseTo,INRESPONSETO,NULL);
                MARSHALL_STRING_ATTRIB(Address,ADDRESS,NULL);
                
                // Take care of wildcard.
                for (map<QName,XMLCh*>::const_iterator i=m_attributeMap.begin(); i!=m_attributeMap.end(); i++) {
                    DOMAttr* attr=domElement->getOwnerDocument()->createAttributeNS(i->first.getNamespaceURI(),i->first.getLocalPart());
                    if (i->first.hasPrefix())
                        attr->setPrefix(i->first.getPrefix());
                    attr->setNodeValue(i->second);
                    domElement->setAttributeNode(attr);
                }
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(KeyInfo,XMLConstants::XMLSIG_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                QName q(attribute->getNamespaceURI(),attribute->getLocalName(),attribute->getPrefix()); 
                setAttribute(q,attribute->getNodeValue());
            }
        };

        class SAML_DLLLOCAL SubjectConfirmationImpl : public virtual SubjectConfirmation,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Method=NULL;
                m_BaseID=NULL;
                m_NameID=NULL;
                m_EncryptedID=NULL;
                m_SubjectConfirmationData=NULL;
                m_KeyInfoConfirmationDataType=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_pos_BaseID=m_children.begin();
                m_pos_NameID=m_pos_BaseID;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
                m_pos_SubjectConfirmationData=m_pos_EncryptedID;
                ++m_pos_SubjectConfirmationData;
                m_pos_KeyInfoConfirmationDataType=m_pos_SubjectConfirmationData;
                ++m_pos_KeyInfoConfirmationDataType;
            }
        public:
            virtual ~SubjectConfirmationImpl() {}
    
            SubjectConfirmationImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            SubjectConfirmationImpl(const SubjectConfirmationImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                if (src.getKeyInfoConfirmationDataType())
                    setKeyInfoConfirmationDataType(src.getKeyInfoConfirmationDataType()->cloneKeyInfoConfirmationDataType());
            }
            
            IMPL_XMLOBJECT_CLONE(SubjectConfirmation);
            IMPL_STRING_ATTRIB(Method);
            IMPL_TYPED_CHILD(BaseID);
            IMPL_TYPED_CHILD(NameID);
            IMPL_TYPED_CHILD(EncryptedID);
            IMPL_XMLOBJECT_CHILD(SubjectConfirmationData);
            IMPL_TYPED_CHILD(KeyInfoConfirmationDataType);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Method,METHOD,NULL);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(BaseID,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(NameID,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(EncryptedID,SAMLConstants::SAML20_NS,false);
                PROC_XMLOBJECT_CHILD(SubjectConfirmationData,SAMLConstants::SAML20_NS);
                PROC_TYPED_CHILD(KeyInfoConfirmationDataType,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Method,METHOD,NULL);
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
                m_BaseID=NULL;
                m_NameID=NULL;
                //m_EncryptedID=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_pos_BaseID=m_children.begin();
                m_pos_NameID=m_pos_BaseID;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
            }
        public:
            virtual ~SubjectImpl() {}
    
            SubjectImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            SubjectImpl(const SubjectImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                PROC_TYPED_CHILD(BaseID,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(NameID,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(EncryptedID,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(SubjectConfirmation,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL SubjectLocalityImpl : public virtual SubjectLocality,
            public AbstractChildlessElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Address=m_DNSName=NULL;
            }
        public:
            virtual ~SubjectLocalityImpl() {
                XMLString::release(&m_Address);
                XMLString::release(&m_DNSName);
            }
    
            SubjectLocalityImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            SubjectLocalityImpl(const SubjectLocalityImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                setAddress(src.getAddress());
                setDNSName(src.getDNSName());
            }
            
            IMPL_XMLOBJECT_CLONE(SubjectLocality);
            IMPL_STRING_ATTRIB(Address);
            IMPL_STRING_ATTRIB(DNSName);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Address,ADDRESS,NULL);
                MARSHALL_STRING_ATTRIB(DNSName,DNSNAME,NULL);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Address,ADDRESS,NULL);
                PROC_STRING_ATTRIB(DNSName,DNSNAME,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AuthnContextDeclImpl : public virtual AuthnContextDecl, public AnyElementImpl
        {
        public:
            virtual ~AuthnContextDeclImpl() {}
    
            AuthnContextDeclImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            AuthnContextDeclImpl(const AuthnContextDeclImpl& src) : AnyElementImpl(src) {
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
                m_AuthnContextClassRef=NULL;
                m_AuthnContextDecl=NULL;
                m_AuthnContextDeclRef=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_pos_AuthnContextClassRef=m_children.begin();
                m_pos_AuthnContextDecl=m_pos_AuthnContextClassRef;
                ++m_pos_AuthnContextDecl;
                m_pos_AuthnContextDeclRef=m_pos_AuthnContextDecl;
                ++m_pos_AuthnContextDeclRef;
            }
        public:
            virtual ~AuthnContextImpl() {}
    
            AuthnContextImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AuthnContextImpl(const AuthnContextImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                PROC_TYPED_CHILD(AuthnContextClassRef,SAMLConstants::SAML20_NS,false);
                PROC_XMLOBJECT_CHILD(AuthnContextDecl,SAMLConstants::SAML20_NS);
                PROC_TYPED_CHILD(AuthnContextDeclRef,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(AuthenticatingAuthority,SAMLConstants::SAML20_NS,false);
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
                m_AuthnInstant=NULL;
                m_SessionIndex=NULL;
                m_SessionNotOnOrAfter=NULL;
                m_SubjectLocality=NULL;
                m_AuthnContext=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
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
    
            AuthnStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AuthnStatementImpl(const AuthnStatementImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                MARSHALL_DATETIME_ATTRIB(AuthnInstant,AUTHNINSTANT,NULL);
                MARSHALL_STRING_ATTRIB(SessionIndex,SESSIONINDEX,NULL);
                MARSHALL_DATETIME_ATTRIB(SessionNotOnOrAfter,SESSIONNOTONORAFTER,NULL);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(SubjectLocality,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(AuthnContext,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_DATETIME_ATTRIB(AuthnInstant,AUTHNINSTANT,NULL);
                PROC_STRING_ATTRIB(SessionIndex,SESSIONINDEX,NULL);
                PROC_DATETIME_ATTRIB(SessionNotOnOrAfter,SESSIONNOTONORAFTER,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL ActionImpl : public virtual Action,
            public AbstractSimpleElement,
            public AbstractChildlessElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~ActionImpl() {
                XMLString::release(&m_Namespace);
            }
    
            ActionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType), m_Namespace(NULL) {
            }
                
            ActionImpl(const ActionImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                setNamespace(src.getNamespace());
            }
            
            IMPL_XMLOBJECT_CLONE(Action);
            IMPL_STRING_ATTRIB(Namespace);
            IMPL_XMLOBJECT_CONTENT;
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Namespace,NAMESPACE,NULL);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Namespace,NAMESPACE,NULL);
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
    
            EvidenceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            EvidenceImpl(const EvidenceImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                PROC_TYPED_CHILDREN(AssertionIDRef,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(AssertionURIRef,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(Assertion,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(EncryptedAssertion,SAMLConstants::SAML20_NS,false);
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
                m_Resource=NULL;
                m_Decision=NULL;
                m_Evidence=NULL;
                m_children.push_back(NULL);
                m_pos_Evidence=m_children.begin();
            }
        public:
            virtual ~AuthzDecisionStatementImpl() {
                XMLString::release(&m_Resource);
                XMLString::release(&m_Decision);
            }
    
            AuthzDecisionStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AuthzDecisionStatementImpl(const AuthzDecisionStatementImpl& src)
                    : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                MARSHALL_STRING_ATTRIB(Resource,RESOURCE,NULL);
                MARSHALL_STRING_ATTRIB(Decision,DECISION,NULL);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Evidence,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(Action,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Resource,RESOURCE,NULL);
                PROC_STRING_ATTRIB(Decision,DECISION,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AttributeValueImpl : public virtual AttributeValue, public AnyElementImpl
        {
        public:
            virtual ~AttributeValueImpl() {}
    
            AttributeValueImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            AttributeValueImpl(const AttributeValueImpl& src) : AnyElementImpl(src) {
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
                m_Name=m_NameFormat=m_FriendlyName=NULL;
            }
        public:
            virtual ~AttributeImpl() {
                XMLString::release(&m_Name);
                XMLString::release(&m_NameFormat);
                XMLString::release(&m_FriendlyName);
            }
    
            AttributeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AttributeImpl(const AttributeImpl& src)
                    : AbstractXMLObject(src), AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
    
            void setAttribute(QName& qualifiedName, const XMLCh* value) {
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
                AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value);
            }

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Name,NAME,NULL);
                MARSHALL_STRING_ATTRIB(NameFormat,NAMEFORMAT,NULL);
                MARSHALL_STRING_ATTRIB(FriendlyName,FRIENDLYNAME,NULL);

                // Take care of wildcard.
                for (map<QName,XMLCh*>::const_iterator i=m_attributeMap.begin(); i!=m_attributeMap.end(); i++) {
                    DOMAttr* attr=domElement->getOwnerDocument()->createAttributeNS(i->first.getNamespaceURI(),i->first.getLocalPart());
                    if (i->first.hasPrefix())
                        attr->setPrefix(i->first.getPrefix());
                    attr->setNodeValue(i->second);
                    domElement->setAttributeNode(attr);
                }
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                getAttributeValues().push_back(childXMLObject);
            }

            void processAttribute(const DOMAttr* attribute) {
                QName q(attribute->getNamespaceURI(),attribute->getLocalName(),attribute->getPrefix()); 
                setAttribute(q,attribute->getNodeValue());
            }
        };

        class SAML_DLLLOCAL EncryptedAttributeImpl : public virtual EncryptedAttribute, public EncryptedElementTypeImpl
        {
        public:
            virtual ~EncryptedAttributeImpl() {}
    
            EncryptedAttributeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
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
    
            AttributeStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            AttributeStatementImpl(const AttributeStatementImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                PROC_TYPED_CHILDREN(Attribute,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(EncryptedAttribute,SAMLConstants::SAML20_NS,false);
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
    
            AdviceImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            AdviceImpl(const AdviceImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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

                        getOthers().push_back((*i)->clone());
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(Advice);
            IMPL_TYPED_CHILDREN(AssertionIDRef,m_children.end());
            IMPL_TYPED_CHILDREN(AssertionURIRef,m_children.end());
            IMPL_TYPED_CHILDREN(Assertion,m_children.end());
            IMPL_TYPED_CHILDREN(EncryptedAssertion,m_children.end());
            IMPL_XMLOBJECT_CHILDREN(Other,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AssertionIDRef,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(AssertionURIRef,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(Assertion,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(EncryptedAssertion,SAMLConstants::SAML20_NS,false);
                
                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAMLConstants::SAML20_NS) && nsURI && *nsURI) {
                    getOthers().push_back(childXMLObject);
                    return;
                }
                
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL EncryptedAssertionImpl : public virtual EncryptedAssertion, public EncryptedElementTypeImpl
        {
        public:
            virtual ~EncryptedAssertionImpl() {}
    
            EncryptedAssertionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
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
                m_ID=NULL;
                m_Version=NULL;
                m_IssueInstant=NULL;
                m_Issuer=NULL;
                m_Signature=NULL;
                m_Subject=NULL;
                m_Conditions=NULL;
                m_Advice=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
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
    
            AssertionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AssertionImpl(const AssertionImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
            
            const XMLCh* getId() const {
                return getID();
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
            IMPL_STRING_ATTRIB(ID);
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
            void marshallAttributes(DOMElement* domElement) const {
                if (!m_Version)
                    const_cast<AssertionImpl*>(this)->m_Version=XMLString::transcode("2.0");
                MARSHALL_STRING_ATTRIB(Version,VER,NULL);
                if (!m_ID)
                    const_cast<AssertionImpl*>(this)->m_ID=SAMLConfig::getConfig().generateIdentifier();
                MARSHALL_ID_ATTRIB(ID,ID,NULL);
                if (!m_IssueInstant) {
                    const_cast<AssertionImpl*>(this)->m_IssueInstantEpoch=time(NULL);
                    const_cast<AssertionImpl*>(this)->m_IssueInstant=new DateTime(m_IssueInstantEpoch);
                }
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Issuer,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(Signature,XMLConstants::XMLSIG_NS,false);
                PROC_TYPED_CHILD(Subject,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(Conditions,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(Advice,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(AuthnStatement,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(AttributeStatement,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(AuthzDecisionStatement,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(Statement,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Version,VER,NULL);
                PROC_ID_ATTRIB(ID,ID,NULL);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
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
IMPL_XMLOBJECTBUILDER(Conditions);
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
const XMLCh EncryptedAssertion::LOCAL_NAME[] =      UNICODE_LITERAL_18(E,n,c,r,y,p,t,e,d,A,s,s,e,r,t,i,o,n);
const XMLCh EncryptedAttribute::LOCAL_NAME[] =      UNICODE_LITERAL_18(E,n,c,r,y,p,t,e,d,A,t,t,r,i,b,u,t,e);
const XMLCh EncryptedElementType::LOCAL_NAME[] =    {chNull};
const XMLCh EncryptedElementType::TYPE_NAME[] =     UNICODE_LITERAL_20(E,n,c,r,y,p,t,e,d,E,l,e,m,e,n,t,T,y,p,e);
const XMLCh EncryptedID::LOCAL_NAME[] =             UNICODE_LITERAL_11(E,n,c,r,y,p,t,e,d,I,d);
const XMLCh Evidence::LOCAL_NAME[] =                UNICODE_LITERAL_8(E,v,i,d,e,n,c,e);
const XMLCh Evidence::TYPE_NAME[] =                 UNICODE_LITERAL_12(E,v,i,d,e,n,c,e,T,y,p,e);
const XMLCh Issuer::LOCAL_NAME[] =                  UNICODE_LITERAL_6(I,s,s,u,e,r);
const XMLCh KeyInfoConfirmationDataType::LOCAL_NAME[] = UNICODE_LITERAL_23(S,u,b,j,e,c,t,C,o,n,f,i,r,m,a,t,i,o,n,D,a,t,a);
const XMLCh KeyInfoConfirmationDataType::TYPE_NAME[] = UNICODE_LITERAL_27(K,e,y,I,n,f,o,C,o,n,f,i,r,m,a,t,i,o,n,D,a,t,a,T,y,p,e);
const XMLCh KeyInfoConfirmationDataType::NOTBEFORE_ATTRIB_NAME[] =      UNICODE_LITERAL_9(N,o,t,B,e,f,o,r,e);
const XMLCh KeyInfoConfirmationDataType::NOTONORAFTER_ATTRIB_NAME[] =   UNICODE_LITERAL_12(N,o,t,O,n,O,r,A,f,t,e,r);
const XMLCh KeyInfoConfirmationDataType::INRESPONSETO_ATTRIB_NAME[] =   UNICODE_LITERAL_12(I,n,R,e,s,p,o,n,s,e,T,o);
const XMLCh KeyInfoConfirmationDataType::RECIPIENT_ATTRIB_NAME[] =      UNICODE_LITERAL_9(R,e,c,i,p,i,e,n,t);
const XMLCh KeyInfoConfirmationDataType::ADDRESS_ATTRIB_NAME[] =        UNICODE_LITERAL_7(A,d,d,r,e,s,s);
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
const XMLCh SubjectConfirmationData::NOTBEFORE_ATTRIB_NAME[] =      UNICODE_LITERAL_9(N,o,t,B,e,f,o,r,e);
const XMLCh SubjectConfirmationData::NOTONORAFTER_ATTRIB_NAME[] =   UNICODE_LITERAL_12(N,o,t,O,n,O,r,A,f,t,e,r);
const XMLCh SubjectConfirmationData::INRESPONSETO_ATTRIB_NAME[] =   UNICODE_LITERAL_12(I,n,R,e,s,p,o,n,s,e,T,o);
const XMLCh SubjectConfirmationData::RECIPIENT_ATTRIB_NAME[] =      UNICODE_LITERAL_9(R,e,c,i,p,i,e,n,t);
const XMLCh SubjectConfirmationData::ADDRESS_ATTRIB_NAME[] =        UNICODE_LITERAL_7(A,d,d,r,e,s,s);
const XMLCh SubjectLocality::LOCAL_NAME[] =         UNICODE_LITERAL_15(S,u,b,j,e,c,t,L,o,c,a,l,i,t,y);
const XMLCh SubjectLocality::TYPE_NAME[] =          UNICODE_LITERAL_19(S,u,b,j,e,c,t,L,o,c,a,l,i,t,y,T,y,p,e);
const XMLCh SubjectLocality::ADDRESS_ATTRIB_NAME[] =UNICODE_LITERAL_7(A,d,d,r,e,s,s);
const XMLCh SubjectLocality::DNSNAME_ATTRIB_NAME[] =UNICODE_LITERAL_7(D,N,S,N,a,m,e);
