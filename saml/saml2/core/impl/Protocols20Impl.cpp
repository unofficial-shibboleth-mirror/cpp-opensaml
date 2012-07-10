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
 * Protocols20Impl.cpp
 * 
 * Implementation classes for SAML 2.0 Protocols schema.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/core/Protocols.h"
#include "signature/ContentReference.h"

#include <xmltooling/AbstractComplexElement.h>
#include <xmltooling/AbstractSimpleElement.h>
#include <xmltooling/encryption/Encryption.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/util/XMLHelper.h>

#include <ctime>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/if.hpp>
#include <boost/lambda/lambda.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml::saml2p;
using namespace xmltooling;
using namespace std;
using xmlconstants::XMLSIG_NS;
using xmlconstants::XMLENC_NS;
using xmlconstants::XML_BOOL_NULL;
using samlconstants::SAML20_NS;
using samlconstants::SAML20P_NS;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {
    namespace saml2p {

        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,Artifact);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,GetComplete);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,NewID);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,RequesterID);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,SessionIndex);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,StatusMessage);

        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,RespondTo);

        class SAML_DLLLOCAL AsynchronousImpl : public virtual Asynchronous,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AsynchronousImpl() {}

            AsynchronousImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            AsynchronousImpl(const AsynchronousImpl& src)
                : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {}

            IMPL_XMLOBJECT_CLONE(Asynchronous);

        protected:
            // has no attributes or children
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
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}
                
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
                if (!XMLString::equals(nsURI,SAML20P_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }
                
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL StatusCodeImpl : public virtual StatusCode,
             public AbstractComplexElement,
             public AbstractDOMCachingXMLObject,
             public AbstractXMLObjectMarshaller,
             public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Value=nullptr;
                m_StatusCode=nullptr;
                m_children.push_back(nullptr);
                m_pos_StatusCode=m_children.begin();
            }

        public:
            virtual ~StatusCodeImpl() {
                XMLString::release(&m_Value);
            }

            StatusCodeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            StatusCodeImpl(const StatusCodeImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Value);
                IMPL_CLONE_TYPED_CHILD(StatusCode);
            }

            IMPL_XMLOBJECT_CLONE(StatusCode);
            IMPL_STRING_ATTRIB(Value);
            IMPL_TYPED_CHILD(StatusCode);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Value,VALUE,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(StatusCode,SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Value,VALUE,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL StatusDetailImpl : public virtual StatusDetail,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~StatusDetailImpl() {}

            StatusDetailImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            StatusDetailImpl(const StatusDetailImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                IMPL_CLONE_XMLOBJECT_CHILDREN(UnknownXMLObject);
            }

            IMPL_XMLOBJECT_CLONE(StatusDetail);
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                getUnknownXMLObjects().push_back(childXMLObject);
            }
        };


        class SAML_DLLLOCAL StatusImpl : public virtual Status,
             public AbstractComplexElement,
             public AbstractDOMCachingXMLObject,
             public AbstractXMLObjectMarshaller,
             public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_StatusCode=nullptr;
                m_StatusMessage=nullptr;
                m_StatusDetail=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_StatusCode=m_children.begin();
                m_pos_StatusMessage=m_pos_StatusCode;
                ++m_pos_StatusMessage;
                m_pos_StatusDetail=m_pos_StatusMessage;
                ++m_pos_StatusDetail;
            }

        public:
            virtual ~StatusImpl() {}
    
            StatusImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            StatusImpl(const StatusImpl& src) : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_TYPED_CHILD(StatusCode);
                IMPL_CLONE_TYPED_CHILD(StatusMessage);
                IMPL_CLONE_TYPED_CHILD(StatusDetail);
            }
            
            IMPL_XMLOBJECT_CLONE(Status);
            IMPL_TYPED_CHILD(StatusCode);
            IMPL_TYPED_CHILD(StatusMessage);
            IMPL_TYPED_CHILD(StatusDetail);
    
            // Base class methods.
            const XMLCh* getTopStatus() const {
                return getStatusCode() ? getStatusCode()->getValue() : nullptr;
            }
            const XMLCh* getSubStatus() const {
                const StatusCode* sc = getStatusCode() ? getStatusCode()->getStatusCode() : nullptr;
                return sc ? sc->getValue() : nullptr;
            }
            bool hasAdditionalStatus() const {
                return (getStatusCode() && getStatusCode()->getStatusCode() && getStatusCode()->getStatusCode()->getStatusCode());
            }
            const XMLCh* getMessage() const {
                return getStatusMessage() ? getStatusMessage()->getMessage() : nullptr;
            }

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(StatusCode,SAML20P_NS,false);
                PROC_TYPED_CHILD(StatusMessage,SAML20P_NS,false);
                PROC_TYPED_CHILD(StatusDetail,SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };


        class SAML_DLLLOCAL RequestAbstractTypeImpl : public virtual RequestAbstractType,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ID=nullptr;
                m_Version=nullptr;
                m_IssueInstant=nullptr;
                m_Destination=nullptr;
                m_Consent=nullptr;
                m_Issuer=nullptr;
                m_Signature=nullptr;
                m_Extensions=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_Issuer=m_children.begin();
                m_pos_Signature=m_pos_Issuer;
                ++m_pos_Signature;
                m_pos_Extensions=m_pos_Signature;
                ++m_pos_Extensions;
            }

        protected:
            RequestAbstractTypeImpl() {
                init();
            }

        public:
            virtual ~RequestAbstractTypeImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_Version);
                XMLString::release(&m_Destination);
                XMLString::release(&m_Consent);
                delete m_IssueInstant;
            }
    
            RequestAbstractTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            RequestAbstractTypeImpl(const RequestAbstractTypeImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
            }

            void _clone(const RequestAbstractTypeImpl& src) {
                IMPL_CLONE_ATTRIB(ID);
                IMPL_CLONE_ATTRIB(Version);
                IMPL_CLONE_ATTRIB(IssueInstant);
                IMPL_CLONE_ATTRIB(Destination);
                IMPL_CLONE_ATTRIB(Consent);
                IMPL_CLONE_TYPED_CHILD(Issuer);
                IMPL_CLONE_TYPED_CHILD(Signature);
                IMPL_CLONE_TYPED_CHILD(Extensions);
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

            RequestAbstractType* cloneRequestAbstractType() const {
                return dynamic_cast<RequestAbstractType*>(clone());
            }
            
            IMPL_STRING_ATTRIB(Version);
            IMPL_ID_ATTRIB_EX(ID,ID,nullptr);
            IMPL_DATETIME_ATTRIB(IssueInstant,0);
            IMPL_STRING_ATTRIB(Destination);
            IMPL_STRING_ATTRIB(Consent);
            IMPL_TYPED_FOREIGN_CHILD(Issuer,saml2);
            IMPL_TYPED_CHILD(Extensions);
    
        protected:
            void prepareForMarshalling() const {
                if (m_Signature)
                    declareNonVisibleNamespaces();
            }

            void marshallAttributes(DOMElement* domElement) const {
                if (!m_Version)
                    const_cast<RequestAbstractTypeImpl*>(this)->m_Version=XMLString::transcode("2.0");
                MARSHALL_STRING_ATTRIB(Version,VER,nullptr);
                if (!m_ID)
                    const_cast<RequestAbstractTypeImpl*>(this)->m_ID=SAMLConfig::getConfig().generateIdentifier();
                MARSHALL_ID_ATTRIB(ID,ID,nullptr);
                if (!m_IssueInstant) {
                    const_cast<RequestAbstractTypeImpl*>(this)->m_IssueInstantEpoch=time(nullptr);
                    const_cast<RequestAbstractTypeImpl*>(this)->m_IssueInstant=new DateTime(m_IssueInstantEpoch);
                }
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,nullptr);
                MARSHALL_STRING_ATTRIB(Destination,DESTINATION,nullptr);
                MARSHALL_STRING_ATTRIB(Consent,CONSENT,nullptr);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Issuer,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(Signature,xmlsignature,XMLSIG_NS,false);
                PROC_TYPED_CHILD(Extensions,SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_ID_ATTRIB(ID,ID,nullptr);
                PROC_STRING_ATTRIB(Version,VER,nullptr);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,nullptr);
                PROC_STRING_ATTRIB(Destination,DESTINATION,nullptr);
                PROC_STRING_ATTRIB(Consent,CONSENT,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };


        class SAML_DLLLOCAL AssertionIDRequestImpl : public virtual AssertionIDRequest, public RequestAbstractTypeImpl
        {
        public:
            virtual ~AssertionIDRequestImpl() {}
    
            AssertionIDRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}
                
            AssertionIDRequestImpl(const AssertionIDRequestImpl& src) : AbstractXMLObject(src), RequestAbstractTypeImpl(src) {}

            void _clone(const AssertionIDRequestImpl& src) {
                RequestAbstractTypeImpl::_clone(src);
                IMPL_CLONE_TYPED_FOREIGN_CHILDREN(AssertionIDRef,saml2);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(AssertionIDRequest);
            IMPL_TYPED_FOREIGN_CHILDREN(AssertionIDRef,saml2,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(AssertionIDRef,saml2,SAML20_NS,false);
                RequestAbstractTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL SubjectQueryImpl : public virtual SubjectQuery, public RequestAbstractTypeImpl
        {
            void init() {
                m_Subject = nullptr;
                m_children.push_back(nullptr);
                m_pos_Subject = m_pos_Extensions;
                ++m_pos_Subject;
            }

        protected:
            SubjectQueryImpl() {
                init();
            }

        public:
            virtual ~SubjectQueryImpl() {}
    
            SubjectQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            SubjectQueryImpl(const SubjectQueryImpl& src) : AbstractXMLObject(src), RequestAbstractTypeImpl(src) {
                init();
            }

            void _clone(const SubjectQueryImpl& src) {
                RequestAbstractTypeImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILD(Subject);
            }
            
            SubjectQuery* cloneSubjectQuery() const {
                return dynamic_cast<SubjectQuery*>(clone());
            }

            IMPL_TYPED_FOREIGN_CHILD(Subject,saml2);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Subject,saml2,SAML20_NS,false);
                RequestAbstractTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL RequestedAuthnContextImpl : public virtual RequestedAuthnContext,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Comparison=nullptr;
            }

        public:
            virtual ~RequestedAuthnContextImpl() {
                XMLString::release(&m_Comparison);
            }
    
            RequestedAuthnContextImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            RequestedAuthnContextImpl(const RequestedAuthnContextImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Comparison);
                IMPL_CLONE_CHILDBAG_BEGIN;
                    IMPL_CLONE_TYPED_FOREIGN_CHILD_IN_BAG(AuthnContextClassRef,saml2);
                    IMPL_CLONE_TYPED_FOREIGN_CHILD_IN_BAG(AuthnContextDeclRef,saml2);
                IMPL_CLONE_CHILDBAG_END;
            }
            
            IMPL_XMLOBJECT_CLONE(RequestedAuthnContext);
            IMPL_STRING_ATTRIB(Comparison);
            IMPL_TYPED_FOREIGN_CHILDREN(AuthnContextClassRef,saml2,m_children.end());
            IMPL_TYPED_FOREIGN_CHILDREN(AuthnContextDeclRef,saml2,m_children.end());
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Comparison,COMPARISON,nullptr);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(AuthnContextClassRef,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(AuthnContextDeclRef,saml2,SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Comparison,COMPARISON,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AuthnQueryImpl : public virtual AuthnQuery, public SubjectQueryImpl
        {
            void init() {
                m_SessionIndex=nullptr;
                m_RequestedAuthnContext=nullptr;
                m_children.push_back(nullptr);
                m_pos_RequestedAuthnContext = m_pos_Subject;
                ++m_pos_RequestedAuthnContext;
                
            }

        public:
            virtual ~AuthnQueryImpl() {
                XMLString::release(&m_SessionIndex);
            }
    
            AuthnQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AuthnQueryImpl(const AuthnQueryImpl& src) : AbstractXMLObject(src), SubjectQueryImpl(src) {
                init();
            }

            void _clone(const AuthnQueryImpl& src) {
                SubjectQueryImpl::_clone(src);
                IMPL_CLONE_ATTRIB(SessionIndex);
                IMPL_CLONE_TYPED_CHILD(RequestedAuthnContext);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(AuthnQuery);
            IMPL_STRING_ATTRIB(SessionIndex);
            IMPL_TYPED_CHILD(RequestedAuthnContext);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(SessionIndex,SESSIONINDEX,nullptr);
                SubjectQueryImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(RequestedAuthnContext,SAML20P_NS,false);
                SubjectQueryImpl::processChildElement(childXMLObject,root);
            }
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(SessionIndex,SESSIONINDEX,nullptr);
                SubjectQueryImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AttributeQueryImpl : public virtual AttributeQuery, public SubjectQueryImpl
        {
        public:
            virtual ~AttributeQueryImpl() {}
    
            AttributeQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}
                
            AttributeQueryImpl(const AttributeQueryImpl& src) : AbstractXMLObject(src), SubjectQueryImpl(src) {}

            void _clone(const AttributeQueryImpl& src) {
                SubjectQueryImpl::_clone(src);
                IMPL_CLONE_TYPED_FOREIGN_CHILDREN(Attribute,saml2);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(AttributeQuery);
            IMPL_TYPED_FOREIGN_CHILDREN(Attribute,saml2,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(Attribute,saml2,SAML20_NS,false);
                SubjectQueryImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthzDecisionQueryImpl : public virtual AuthzDecisionQuery, public SubjectQueryImpl
        {
            void init() {
                m_Resource=nullptr;
                m_Evidence=nullptr;
                m_children.push_back(nullptr);
                m_pos_Evidence=m_pos_Subject;
                ++m_pos_Evidence;   
            }

        public:
            virtual ~AuthzDecisionQueryImpl() {
                XMLString::release(&m_Resource);
            }
    
            AuthzDecisionQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AuthzDecisionQueryImpl(const AuthzDecisionQueryImpl& src) : AbstractXMLObject(src), SubjectQueryImpl(src) {
                init();
            }

            void _clone(const AuthzDecisionQueryImpl& src) {
                SubjectQueryImpl::_clone(src);
                IMPL_CLONE_ATTRIB(Resource);
                IMPL_CLONE_TYPED_CHILD(Evidence);
                IMPL_CLONE_TYPED_FOREIGN_CHILDREN(Action,saml2);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(AuthzDecisionQuery);
            IMPL_STRING_ATTRIB(Resource);
            IMPL_TYPED_FOREIGN_CHILDREN(Action,saml2,m_pos_Evidence);
            IMPL_TYPED_FOREIGN_CHILD(Evidence,saml2);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Resource,RESOURCE,nullptr);
                SubjectQueryImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Evidence,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(Action,saml2,SAML20_NS,false);
                SubjectQueryImpl::processChildElement(childXMLObject,root);
            }
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Resource,RESOURCE,nullptr);
                SubjectQueryImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL NameIDPolicyImpl : public virtual NameIDPolicy,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Format=nullptr;
                m_SPNameQualifier=nullptr;
                m_AllowCreate=XML_BOOL_NULL;
            }

        public:
            virtual ~NameIDPolicyImpl() {
                XMLString::release(&m_Format);
                XMLString::release(&m_SPNameQualifier);
            }

            NameIDPolicyImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            NameIDPolicyImpl(const NameIDPolicyImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(Format);
                IMPL_CLONE_ATTRIB(SPNameQualifier);
                IMPL_CLONE_BOOLEAN_ATTRIB(AllowCreate);
            }

            IMPL_XMLOBJECT_CLONE(NameIDPolicy);
            IMPL_STRING_ATTRIB(Format);
            IMPL_STRING_ATTRIB(SPNameQualifier);
            IMPL_BOOLEAN_ATTRIB(AllowCreate);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Format,FORMAT,nullptr);
                MARSHALL_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER,nullptr);
                MARSHALL_BOOLEAN_ATTRIB(AllowCreate,ALLOWCREATE,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Format,FORMAT,nullptr);
                PROC_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER,nullptr);
                PROC_BOOLEAN_ATTRIB(AllowCreate,ALLOWCREATE,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL IDPEntryImpl : public virtual IDPEntry,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ProviderID=nullptr;
                m_Name=nullptr;
                m_Loc=nullptr;
            }

        public:
            virtual ~IDPEntryImpl() {
                XMLString::release(&m_ProviderID);
                XMLString::release(&m_Name);
                XMLString::release(&m_Loc);
            }

            IDPEntryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            IDPEntryImpl(const IDPEntryImpl& src) : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_ATTRIB(ProviderID);
                IMPL_CLONE_ATTRIB(Name);
                IMPL_CLONE_ATTRIB(Loc);
            }

            IMPL_XMLOBJECT_CLONE(IDPEntry);
            IMPL_STRING_ATTRIB(ProviderID);
            IMPL_STRING_ATTRIB(Name);
            IMPL_STRING_ATTRIB(Loc);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(ProviderID,PROVIDERID,nullptr);
                MARSHALL_STRING_ATTRIB(Name,NAME,nullptr);
                MARSHALL_STRING_ATTRIB(Loc,LOC,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(ProviderID,PROVIDERID,nullptr);
                PROC_STRING_ATTRIB(Name,NAME,nullptr);
                PROC_STRING_ATTRIB(Loc,LOC,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL IDPListImpl : public virtual IDPList,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_GetComplete=nullptr;
                m_children.push_back(nullptr);
                m_pos_GetComplete=m_children.begin();
            }

        public:
            virtual ~IDPListImpl() {}
    
            IDPListImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            IDPListImpl(const IDPListImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_TYPED_CHILD(GetComplete);
                IMPL_CLONE_TYPED_CHILDREN(IDPEntry);
            }
            
            IMPL_XMLOBJECT_CLONE(IDPList);
            IMPL_TYPED_CHILDREN(IDPEntry,m_pos_GetComplete);
            IMPL_TYPED_CHILD(GetComplete);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(IDPEntry,SAML20P_NS,false);
                PROC_TYPED_CHILD(GetComplete,SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };


        class SAML_DLLLOCAL ScopingImpl : public virtual Scoping,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ProxyCount=nullptr;
                m_IDPList=nullptr;
                m_children.push_back(nullptr);
                m_pos_IDPList=m_children.begin();
            }

        public:
            virtual ~ScopingImpl() {
                XMLString::release(&m_ProxyCount); 
            }
    
            ScopingImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            ScopingImpl(const ScopingImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_INTEGER_ATTRIB(ProxyCount);
                IMPL_CLONE_TYPED_CHILD(IDPList);
                IMPL_CLONE_TYPED_CHILDREN(RequesterID);
            }
            
            IMPL_XMLOBJECT_CLONE(Scoping);
            IMPL_INTEGER_ATTRIB(ProxyCount);
            IMPL_TYPED_CHILD(IDPList);
            IMPL_TYPED_CHILDREN(RequesterID,m_children.end());
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_INTEGER_ATTRIB(ProxyCount,PROXYCOUNT,nullptr);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(IDPList,SAML20P_NS,false);
                PROC_TYPED_CHILDREN(RequesterID,SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_INTEGER_ATTRIB(ProxyCount,PROXYCOUNT,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AuthnRequestImpl : public virtual AuthnRequest, public RequestAbstractTypeImpl
        {
            void init() {
                m_ForceAuthn=XML_BOOL_NULL;
                m_IsPassive=XML_BOOL_NULL;
                m_ProtocolBinding=nullptr;
                m_AssertionConsumerServiceIndex=nullptr;
                m_AssertionConsumerServiceURL=nullptr;
                m_AttributeConsumingServiceIndex=nullptr;
                m_ProviderName=nullptr;

                m_Subject=nullptr;
                m_NameIDPolicy=nullptr;
                m_Conditions=nullptr;
                m_RequestedAuthnContext=nullptr;
                m_Scoping=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_Subject=m_pos_Extensions;
                ++m_pos_Subject;
                m_pos_NameIDPolicy=m_pos_Subject;
                ++m_pos_NameIDPolicy;
                m_pos_Conditions=m_pos_NameIDPolicy;
                ++m_pos_Conditions;
                m_pos_RequestedAuthnContext=m_pos_Conditions;
                ++m_pos_RequestedAuthnContext;
                m_pos_Scoping=m_pos_RequestedAuthnContext;
                ++m_pos_Scoping;
            }

        public:
            virtual ~AuthnRequestImpl() {
                XMLString::release(&m_ProtocolBinding);
                XMLString::release(&m_AssertionConsumerServiceURL);
                XMLString::release(&m_ProviderName);
                XMLString::release(&m_AssertionConsumerServiceIndex);
                XMLString::release(&m_AttributeConsumingServiceIndex);
            }
    
            AuthnRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AuthnRequestImpl(const AuthnRequestImpl& src) : AbstractXMLObject(src), RequestAbstractTypeImpl(src) {
                init();
            }

            void _clone(const AuthnRequestImpl& src) {
                RequestAbstractTypeImpl::_clone(src);
                IMPL_CLONE_BOOLEAN_ATTRIB(ForceAuthn);
                IMPL_CLONE_BOOLEAN_ATTRIB(IsPassive);
                IMPL_CLONE_ATTRIB(ProtocolBinding);
                IMPL_CLONE_INTEGER_ATTRIB(AssertionConsumerServiceIndex);
                IMPL_CLONE_ATTRIB(AssertionConsumerServiceURL);
                IMPL_CLONE_INTEGER_ATTRIB(AttributeConsumingServiceIndex);
                IMPL_CLONE_ATTRIB(ProviderName);
                IMPL_CLONE_TYPED_CHILD(Subject);
                IMPL_CLONE_TYPED_CHILD(NameIDPolicy);
                IMPL_CLONE_TYPED_CHILD(Conditions);
                IMPL_CLONE_TYPED_CHILD(RequestedAuthnContext);
                IMPL_CLONE_TYPED_CHILD(Scoping);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(AuthnRequest);

            IMPL_BOOLEAN_ATTRIB(ForceAuthn);
            IMPL_BOOLEAN_ATTRIB(IsPassive);
            IMPL_STRING_ATTRIB(ProtocolBinding);
            IMPL_INTEGER_ATTRIB(AssertionConsumerServiceIndex);
            IMPL_STRING_ATTRIB(AssertionConsumerServiceURL);
            IMPL_INTEGER_ATTRIB(AttributeConsumingServiceIndex);
            IMPL_STRING_ATTRIB(ProviderName);

            IMPL_TYPED_FOREIGN_CHILD(Subject,saml2);
            IMPL_TYPED_CHILD(NameIDPolicy);
            IMPL_TYPED_FOREIGN_CHILD(Conditions,saml2);
            IMPL_TYPED_CHILD(RequestedAuthnContext);
            IMPL_TYPED_CHILD(Scoping);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_BOOLEAN_ATTRIB(ForceAuthn,FORCEAUTHN,nullptr);
                MARSHALL_BOOLEAN_ATTRIB(IsPassive,ISPASSIVE,nullptr);
                MARSHALL_STRING_ATTRIB(ProtocolBinding,PROTOCOLBINDING,nullptr);
                MARSHALL_INTEGER_ATTRIB(AssertionConsumerServiceIndex,ASSERTIONCONSUMERSERVICEINDEX,nullptr);
                MARSHALL_STRING_ATTRIB(AssertionConsumerServiceURL,ASSERTIONCONSUMERSERVICEURL,nullptr);
                MARSHALL_INTEGER_ATTRIB(AttributeConsumingServiceIndex,ATTRIBUTECONSUMINGSERVICEINDEX,nullptr);
                MARSHALL_STRING_ATTRIB(ProviderName,PROVIDERNAME,nullptr);
                RequestAbstractTypeImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Subject,saml2,SAML20_NS,false);
                PROC_TYPED_CHILD(NameIDPolicy,SAML20P_NS,false);
                PROC_TYPED_FOREIGN_CHILD(Conditions,saml2,SAML20_NS,false);
                PROC_TYPED_CHILD(RequestedAuthnContext,SAML20P_NS,false);
                PROC_TYPED_CHILD(Scoping,SAML20P_NS,false);
                RequestAbstractTypeImpl::processChildElement(childXMLObject,root);
            }
            void processAttribute(const DOMAttr* attribute) {
                PROC_BOOLEAN_ATTRIB(ForceAuthn,FORCEAUTHN,nullptr);
                PROC_BOOLEAN_ATTRIB(IsPassive,ISPASSIVE,nullptr);
                PROC_STRING_ATTRIB(ProtocolBinding,PROTOCOLBINDING,nullptr);
                PROC_INTEGER_ATTRIB(AssertionConsumerServiceIndex,ASSERTIONCONSUMERSERVICEINDEX,nullptr);
                PROC_STRING_ATTRIB(AssertionConsumerServiceURL,ASSERTIONCONSUMERSERVICEURL,nullptr);
                PROC_INTEGER_ATTRIB(AttributeConsumingServiceIndex,ATTRIBUTECONSUMINGSERVICEINDEX,nullptr);
                PROC_STRING_ATTRIB(ProviderName,PROVIDERNAME,nullptr);
                RequestAbstractTypeImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL StatusResponseTypeImpl : public virtual StatusResponseType,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ID=nullptr;
                m_InResponseTo=nullptr;
                m_Version=nullptr;
                m_IssueInstant=nullptr;
                m_Destination=nullptr;
                m_Consent=nullptr;
                m_Issuer=nullptr;
                m_Signature=nullptr;
                m_Extensions=nullptr;
                m_Status=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_Issuer=m_children.begin();
                m_pos_Signature=m_pos_Issuer;
                ++m_pos_Signature;
                m_pos_Extensions=m_pos_Signature;
                ++m_pos_Extensions;
                m_pos_Status=m_pos_Extensions;
                ++m_pos_Status;
            }

        protected:
            StatusResponseTypeImpl() {
                init();
            }

        public:
            virtual ~StatusResponseTypeImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_InResponseTo);
                XMLString::release(&m_Version);
                XMLString::release(&m_Destination);
                XMLString::release(&m_Consent);
                delete m_IssueInstant;
            }
    
            StatusResponseTypeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            StatusResponseTypeImpl(const StatusResponseTypeImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
            }

            void _clone(const StatusResponseTypeImpl& src) {
                IMPL_CLONE_ATTRIB(ID);
                IMPL_CLONE_ATTRIB(InResponseTo);
                IMPL_CLONE_ATTRIB(Version);
                IMPL_CLONE_ATTRIB(IssueInstant);
                IMPL_CLONE_ATTRIB(Destination);
                IMPL_CLONE_ATTRIB(Consent);
                IMPL_CLONE_TYPED_CHILD(Issuer);
                IMPL_CLONE_TYPED_CHILD(Signature);
                IMPL_CLONE_TYPED_CHILD(Extensions);
                IMPL_CLONE_TYPED_CHILD(Status);
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
            
            StatusResponseType* cloneStatusResponseType() const {
                return dynamic_cast<StatusResponseType*>(clone());
            }

            IMPL_STRING_ATTRIB(Version);
            IMPL_ID_ATTRIB_EX(ID,ID,nullptr);
            IMPL_STRING_ATTRIB(InResponseTo);
            IMPL_DATETIME_ATTRIB(IssueInstant,0);
            IMPL_STRING_ATTRIB(Destination);
            IMPL_STRING_ATTRIB(Consent);
            IMPL_TYPED_FOREIGN_CHILD(Issuer,saml2);
            IMPL_TYPED_CHILD(Extensions);
            IMPL_TYPED_CHILD(Status);
    
        protected:
            void prepareForMarshalling() const {
                if (m_Signature)
                    declareNonVisibleNamespaces();
            }

            void marshallAttributes(DOMElement* domElement) const {
                if (!m_Version)
                    const_cast<StatusResponseTypeImpl*>(this)->m_Version=XMLString::transcode("2.0");
                MARSHALL_STRING_ATTRIB(Version,VER,nullptr);
                if (!m_ID)
                    const_cast<StatusResponseTypeImpl*>(this)->m_ID=SAMLConfig::getConfig().generateIdentifier();
                MARSHALL_ID_ATTRIB(ID,ID,nullptr);
                if (!m_IssueInstant) {
                    const_cast<StatusResponseTypeImpl*>(this)->m_IssueInstantEpoch=time(nullptr);
                    const_cast<StatusResponseTypeImpl*>(this)->m_IssueInstant=new DateTime(m_IssueInstantEpoch);
                }
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,nullptr);
                MARSHALL_STRING_ATTRIB(Destination,DESTINATION,nullptr);
                MARSHALL_STRING_ATTRIB(Consent,CONSENT,nullptr);
                MARSHALL_STRING_ATTRIB(InResponseTo,INRESPONSETO,nullptr);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Issuer,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(Signature,xmlsignature,XMLSIG_NS,false);
                PROC_TYPED_CHILD(Extensions,SAML20P_NS,false);
                PROC_TYPED_CHILD(Status,SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_ID_ATTRIB(ID,ID,nullptr);
                PROC_STRING_ATTRIB(Version,VER,nullptr);
                PROC_STRING_ATTRIB(InResponseTo,INRESPONSETO,nullptr);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,nullptr);
                PROC_STRING_ATTRIB(Destination,DESTINATION,nullptr);
                PROC_STRING_ATTRIB(Consent,CONSENT,nullptr);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL ResponseImpl : public virtual Response, public StatusResponseTypeImpl
        {
        public:
            virtual ~ResponseImpl() {}
    
            ResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}
                
            ResponseImpl(const ResponseImpl& src) : AbstractXMLObject(src), StatusResponseTypeImpl(src) {}

            void _clone(const ResponseImpl& src) {
                StatusResponseTypeImpl::_clone(src);
                IMPL_CLONE_CHILDBAG_BEGIN;
                    IMPL_CLONE_TYPED_FOREIGN_CHILD_IN_BAG(Assertion,saml2);
                    IMPL_CLONE_TYPED_FOREIGN_CHILD_IN_BAG(EncryptedAssertion,saml2);
                IMPL_CLONE_CHILDBAG_END;
            }
            
            IMPL_XMLOBJECT_CLONE_EX(Response);
            IMPL_TYPED_FOREIGN_CHILDREN(Assertion,saml2,m_children.end());
            IMPL_TYPED_FOREIGN_CHILDREN(EncryptedAssertion,saml2,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(Assertion,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(EncryptedAssertion,saml2,SAML20_NS,false);
                StatusResponseTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL ArtifactResolveImpl : public virtual ArtifactResolve, public RequestAbstractTypeImpl
        {
            void init() {
                m_Artifact=nullptr;
                m_children.push_back(nullptr);
                m_pos_Artifact=m_pos_Extensions;
                ++m_pos_Artifact;
            }

        public:
            virtual ~ArtifactResolveImpl() {}
    
            ArtifactResolveImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            ArtifactResolveImpl(const ArtifactResolveImpl& src) : AbstractXMLObject(src), RequestAbstractTypeImpl(src) {
                init();
            }

            void _clone(const ArtifactResolveImpl& src) {
                RequestAbstractTypeImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILD(Artifact);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(ArtifactResolve);
            IMPL_TYPED_CHILD(Artifact);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Artifact,SAML20P_NS,false);
                RequestAbstractTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL ArtifactResponseImpl : public virtual ArtifactResponse, public StatusResponseTypeImpl
        {
            void init() {
                m_Payload=nullptr;
                m_children.push_back(nullptr);
                m_pos_Payload=m_pos_Status;
                ++m_pos_Payload;
            }

        public:
            virtual ~ArtifactResponseImpl() {}
    
            ArtifactResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            ArtifactResponseImpl(const ArtifactResponseImpl& src) : AbstractXMLObject(src), StatusResponseTypeImpl(src) {
                init();
            }

            void _clone(const ArtifactResponseImpl& src) {
                StatusResponseTypeImpl::_clone(src);
                IMPL_CLONE_XMLOBJECT_CHILD(Payload);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(ArtifactResponse);
            IMPL_XMLOBJECT_CHILD(Payload);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                // These are valid elements for the parent StatusResponseType, so don't process these.
                // If not one of these, then it must be the payload.
                if (!XMLHelper::isNodeNamed(root,SAML20_NS,saml2::Issuer::LOCAL_NAME) &&
                    !XMLHelper::isNodeNamed(root,XMLSIG_NS,xmlsignature::Signature::LOCAL_NAME) &&
                    !XMLHelper::isNodeNamed(root,SAML20P_NS,saml2p::Extensions::LOCAL_NAME) &&
                    !XMLHelper::isNodeNamed(root,SAML20P_NS,saml2p::Status::LOCAL_NAME)) {
                    setPayload(childXMLObject);
                    return;
                }

                StatusResponseTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL NewEncryptedIDImpl : public virtual NewEncryptedID,
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
            NewEncryptedIDImpl() {
                init();
            }
            
        public:
            virtual ~NewEncryptedIDImpl() {}
    
            NewEncryptedIDImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            NewEncryptedIDImpl(const NewEncryptedIDImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                IMPL_CLONE_TYPED_CHILD(EncryptedData);
                IMPL_CLONE_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption);
            }
    
            IMPL_XMLOBJECT_CLONE2(NewEncryptedID,EncryptedElementType);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption);
            IMPL_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption,XMLENC_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption,XMLENC_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL TerminateImpl : public virtual Terminate,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~TerminateImpl() {}

            TerminateImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}

            TerminateImpl(const TerminateImpl& src)
                : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {}

            IMPL_XMLOBJECT_CLONE(Terminate);

        protected:
            // has no attributes or children
        };

        class SAML_DLLLOCAL ManageNameIDRequestImpl : public virtual ManageNameIDRequest, public RequestAbstractTypeImpl
        {
            void init() {
                m_NameID=nullptr;
                m_EncryptedID=nullptr;
                m_NewID=nullptr;
                m_NewEncryptedID=nullptr;
                m_Terminate=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_NameID=m_pos_Extensions;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
                m_pos_NewID=m_pos_EncryptedID;
                ++m_pos_NewID;
                m_pos_NewEncryptedID=m_pos_NewID;
                ++m_pos_NewEncryptedID;
                m_pos_Terminate=m_pos_NewEncryptedID;
                ++m_pos_Terminate;
            }

        public:
            virtual ~ManageNameIDRequestImpl() {}
    
            ManageNameIDRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            ManageNameIDRequestImpl(const ManageNameIDRequestImpl& src) : AbstractXMLObject(src), RequestAbstractTypeImpl(src) {
                init();
            }

            void _clone(const ManageNameIDRequestImpl& src) {
                RequestAbstractTypeImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILD(NameID);
                IMPL_CLONE_TYPED_CHILD(EncryptedID);
                IMPL_CLONE_TYPED_CHILD(NewID);
                IMPL_CLONE_TYPED_CHILD(NewEncryptedID);
                IMPL_CLONE_TYPED_CHILD(Terminate);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(ManageNameIDRequest);
            IMPL_TYPED_FOREIGN_CHILD(NameID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            IMPL_TYPED_CHILD(NewID);
            IMPL_TYPED_CHILD(NewEncryptedID);
            IMPL_TYPED_CHILD(Terminate);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(NameID,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(EncryptedID,saml2,SAML20_NS,false);
                PROC_TYPED_CHILD(NewID,SAML20P_NS,false);
                PROC_TYPED_CHILD(NewEncryptedID,SAML20P_NS,false);
                PROC_TYPED_CHILD(Terminate,SAML20P_NS,false);
                RequestAbstractTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL ManageNameIDResponseImpl : public virtual ManageNameIDResponse, public StatusResponseTypeImpl
        {
        public:
            virtual ~ManageNameIDResponseImpl() {}

            ManageNameIDResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}
            
            ManageNameIDResponseImpl(const ManageNameIDResponseImpl& src) : AbstractXMLObject(src), StatusResponseTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(ManageNameIDResponse);
        };

        class SAML_DLLLOCAL LogoutRequestImpl : public virtual LogoutRequest, public RequestAbstractTypeImpl
        {
            void init() {
                m_Reason=nullptr;
                m_NotOnOrAfter=nullptr;
                m_BaseID=nullptr;
                m_NameID=nullptr;
                m_EncryptedID=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_BaseID=m_pos_Extensions;
                ++m_pos_BaseID;
                m_pos_NameID=m_pos_BaseID;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
            }

        public:
            virtual ~LogoutRequestImpl() {
                XMLString::release(&m_Reason);
                delete m_NotOnOrAfter;
            }
    
            LogoutRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            LogoutRequestImpl(const LogoutRequestImpl& src) : AbstractXMLObject(src), RequestAbstractTypeImpl(src) {
                init();
            }

            void _clone(const LogoutRequestImpl& src) {
                RequestAbstractTypeImpl::_clone(src);
                IMPL_CLONE_ATTRIB(Reason);
                IMPL_CLONE_ATTRIB(NotOnOrAfter);
                IMPL_CLONE_TYPED_CHILD(BaseID);
                IMPL_CLONE_TYPED_CHILD(NameID);
                IMPL_CLONE_TYPED_CHILD(EncryptedID);
                IMPL_CLONE_TYPED_CHILDREN(SessionIndex);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(LogoutRequest);
            IMPL_STRING_ATTRIB(Reason);
            IMPL_DATETIME_ATTRIB(NotOnOrAfter,SAMLTIME_MAX);
            IMPL_TYPED_FOREIGN_CHILD(BaseID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(NameID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            IMPL_TYPED_CHILDREN(SessionIndex,m_children.end());
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Reason,REASON,nullptr);
                MARSHALL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
                RequestAbstractTypeImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(BaseID,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(NameID,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(EncryptedID,saml2,SAML20_NS,false);
                PROC_TYPED_CHILDREN(SessionIndex,SAML20P_NS,false);
                RequestAbstractTypeImpl::processChildElement(childXMLObject,root);
            }
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Reason,REASON,nullptr);
                PROC_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
                RequestAbstractTypeImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL LogoutResponseImpl : public virtual LogoutResponse, public StatusResponseTypeImpl
        {
        public:
            virtual ~LogoutResponseImpl() {}

            LogoutResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {}
            
            LogoutResponseImpl(const LogoutResponseImpl& src) : AbstractXMLObject(src), StatusResponseTypeImpl(src) {}

            IMPL_XMLOBJECT_CLONE_EX(LogoutResponse);
        };


        class SAML_DLLLOCAL NameIDMappingRequestImpl : public virtual NameIDMappingRequest, public RequestAbstractTypeImpl
        {
            void init() {
                m_BaseID=nullptr;
                m_NameID=nullptr;
                m_EncryptedID=nullptr;
                m_NameIDPolicy=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_BaseID=m_pos_Extensions;
                ++m_pos_BaseID;
                m_pos_NameID=m_pos_BaseID;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
                m_pos_NameIDPolicy=m_pos_EncryptedID;
                ++m_pos_NameIDPolicy;
            }

        public:
            virtual ~NameIDMappingRequestImpl() {}
    
            NameIDMappingRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            NameIDMappingRequestImpl(const NameIDMappingRequestImpl& src) : AbstractXMLObject(src), RequestAbstractTypeImpl(src) {
                init();
            }

            void _clone(const NameIDMappingRequestImpl& src) {
                RequestAbstractTypeImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILD(BaseID);
                IMPL_CLONE_TYPED_CHILD(NameID);
                IMPL_CLONE_TYPED_CHILD(EncryptedID);
                IMPL_CLONE_TYPED_CHILD(NameIDPolicy);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(NameIDMappingRequest);
            IMPL_TYPED_FOREIGN_CHILD(BaseID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(NameID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            IMPL_TYPED_CHILD(NameIDPolicy);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(BaseID,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(NameID,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(EncryptedID,saml2,SAML20_NS,false);
                PROC_TYPED_CHILD(NameIDPolicy,SAML20P_NS,false);
                RequestAbstractTypeImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL NameIDMappingResponseImpl : public virtual NameIDMappingResponse, public StatusResponseTypeImpl
        {
            void init() {
                m_NameID=nullptr;
                m_EncryptedID=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_NameID=m_pos_Status;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
            }

        public:
            virtual ~NameIDMappingResponseImpl() {}
    
            NameIDMappingResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            NameIDMappingResponseImpl(const NameIDMappingResponseImpl& src) : AbstractXMLObject(src), StatusResponseTypeImpl(src) {
                init();
            }

            void _clone(const NameIDMappingResponseImpl& src) {
                StatusResponseTypeImpl::_clone(src);
                IMPL_CLONE_TYPED_CHILD(NameID);
                IMPL_CLONE_TYPED_CHILD(EncryptedID);
            }
            
            IMPL_XMLOBJECT_CLONE_EX(NameIDMappingResponse);
            IMPL_TYPED_FOREIGN_CHILD(NameID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(NameID,saml2,SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(EncryptedID,saml2,SAML20_NS,false);
                StatusResponseTypeImpl::processChildElement(childXMLObject,root);
            }
        };
    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

// Builder Implementations
IMPL_XMLOBJECTBUILDER(Artifact);
IMPL_XMLOBJECTBUILDER(ArtifactResolve);
IMPL_XMLOBJECTBUILDER(ArtifactResponse);
IMPL_XMLOBJECTBUILDER(AssertionIDRequest);
IMPL_XMLOBJECTBUILDER(AttributeQuery);
IMPL_XMLOBJECTBUILDER(AuthnQuery);
IMPL_XMLOBJECTBUILDER(AuthnRequest);
IMPL_XMLOBJECTBUILDER(AuthzDecisionQuery);
IMPL_XMLOBJECTBUILDER(Extensions);
IMPL_XMLOBJECTBUILDER(GetComplete);
IMPL_XMLOBJECTBUILDER(IDPEntry);
IMPL_XMLOBJECTBUILDER(IDPList);
IMPL_XMLOBJECTBUILDER(LogoutRequest);
IMPL_XMLOBJECTBUILDER(LogoutResponse);
IMPL_XMLOBJECTBUILDER(ManageNameIDRequest);
IMPL_XMLOBJECTBUILDER(ManageNameIDResponse);
IMPL_XMLOBJECTBUILDER(NameIDMappingRequest);
IMPL_XMLOBJECTBUILDER(NameIDMappingResponse);
IMPL_XMLOBJECTBUILDER(NameIDPolicy);
IMPL_XMLOBJECTBUILDER(NewEncryptedID);
IMPL_XMLOBJECTBUILDER(NewID);
IMPL_XMLOBJECTBUILDER(RequestedAuthnContext);
IMPL_XMLOBJECTBUILDER(RequesterID);
IMPL_XMLOBJECTBUILDER(Response);
IMPL_XMLOBJECTBUILDER(Scoping);
IMPL_XMLOBJECTBUILDER(SessionIndex);
IMPL_XMLOBJECTBUILDER(Status);
IMPL_XMLOBJECTBUILDER(StatusCode);
IMPL_XMLOBJECTBUILDER(StatusDetail);
IMPL_XMLOBJECTBUILDER(StatusMessage);
IMPL_XMLOBJECTBUILDER(Terminate);

IMPL_XMLOBJECTBUILDER(RespondTo);
IMPL_XMLOBJECTBUILDER(Asynchronous);

// Unicode literals
const XMLCh Artifact::LOCAL_NAME[] = UNICODE_LITERAL_8(A,r,t,i,f,a,c,t);
const XMLCh ArtifactResolve::LOCAL_NAME[] = UNICODE_LITERAL_15(A,r,t,i,f,a,c,t,R,e,s,o,l,v,e);
const XMLCh ArtifactResolve::TYPE_NAME[] = UNICODE_LITERAL_19(A,r,t,i,f,a,c,t,R,e,s,o,l,v,e,T,y,p,e);
const XMLCh ArtifactResponse::LOCAL_NAME[] = UNICODE_LITERAL_16(A,r,t,i,f,a,c,t,R,e,s,p,o,n,s,e);
const XMLCh ArtifactResponse::TYPE_NAME[] = UNICODE_LITERAL_20(A,r,t,i,f,a,c,t,R,e,s,p,o,n,s,e,T,y,p,e);
const XMLCh AssertionIDRequest::LOCAL_NAME[] = UNICODE_LITERAL_18(A,s,s,e,r,t,i,o,n,I,D,R,e,q,u,e,s,t);
const XMLCh AssertionIDRequest::TYPE_NAME[] = UNICODE_LITERAL_22(A,s,s,e,r,t,i,o,n,I,D,R,e,q,u,e,s,t,T,y,p,e);
const XMLCh Asynchronous::LOCAL_NAME[] = UNICODE_LITERAL_12(A,s,y,n,c,h,r,o,n,o,u,s);
const XMLCh Asynchronous::TYPE_NAME[] = UNICODE_LITERAL_16(A,s,y,n,c,h,r,o,n,o,u,s,T,y,p,e);
const XMLCh AttributeQuery::LOCAL_NAME[] = UNICODE_LITERAL_14(A,t,t,r,i,b,u,t,e,Q,u,e,r,y);
const XMLCh AttributeQuery::TYPE_NAME[] = UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,Q,u,e,r,y,T,y,p,e);
const XMLCh AuthnQuery::LOCAL_NAME[] = UNICODE_LITERAL_10(A,u,t,h,n,Q,u,e,r,y);
const XMLCh AuthnQuery::TYPE_NAME[] = UNICODE_LITERAL_14(A,u,t,h,n,Q,u,e,r,y,T,y,p,e);
const XMLCh AuthnQuery::SESSIONINDEX_ATTRIB_NAME[] = UNICODE_LITERAL_12(S,e,s,s,i,o,n,I,n,d,e,x);
const XMLCh AuthnRequest::LOCAL_NAME[] = UNICODE_LITERAL_12(A,u,t,h,n,R,e,q,u,e,s,t);
const XMLCh AuthnRequest::TYPE_NAME[] = UNICODE_LITERAL_16(A,u,t,h,n,R,e,q,u,e,s,t,T,y,p,e);
const XMLCh AuthnRequest::FORCEAUTHN_ATTRIB_NAME[] = UNICODE_LITERAL_10(F,o,r,c,e,A,u,t,h,n);
const XMLCh AuthnRequest::ISPASSIVE_ATTRIB_NAME[] = UNICODE_LITERAL_9(I,s,P,a,s,s,i,v,e);
const XMLCh AuthnRequest::PROTOCOLBINDING_ATTRIB_NAME[] = UNICODE_LITERAL_15(P,r,o,t,o,c,o,l,B,i,n,d,i,n,g);
const XMLCh AuthnRequest::ASSERTIONCONSUMERSERVICEINDEX_ATTRIB_NAME[] = UNICODE_LITERAL_29(A,s,s,e,r,t,i,o,n,C,o,n,s,u,m,e,r,S,e,r,v,i,c,e,I,n,d,e,x);
const XMLCh AuthnRequest::ASSERTIONCONSUMERSERVICEURL_ATTRIB_NAME[] = UNICODE_LITERAL_27(A,s,s,e,r,t,i,o,n,C,o,n,s,u,m,e,r,S,e,r,v,i,c,e,U,R,L);
const XMLCh AuthnRequest::ATTRIBUTECONSUMINGSERVICEINDEX_ATTRIB_NAME[] = UNICODE_LITERAL_30(A,t,t,r,i,b,u,t,e,C,o,n,s,u,m,i,n,g,S,e,r,v,i,c,e,I,n,d,e,x);
const XMLCh AuthnRequest::PROVIDERNAME_ATTRIB_NAME[] = UNICODE_LITERAL_12(P,r,o,v,i,d,e,r,N,a,m,e);
const XMLCh AuthzDecisionQuery::LOCAL_NAME[] = UNICODE_LITERAL_18(A,u,t,h,z,D,e,c,i,s,i,o,n,Q,u,e,r,y);
const XMLCh AuthzDecisionQuery::TYPE_NAME[] = UNICODE_LITERAL_22(A,u,t,h,z,D,e,c,i,s,i,o,n,Q,u,e,r,y,T,y,p,e);
const XMLCh AuthzDecisionQuery::RESOURCE_ATTRIB_NAME[] = UNICODE_LITERAL_8(R,e,s,o,u,r,c,e);
const XMLCh Extensions::LOCAL_NAME[] = UNICODE_LITERAL_10(E,x,t,e,n,s,i,o,n,s);
const XMLCh Extensions::TYPE_NAME[] = UNICODE_LITERAL_14(E,x,t,e,n,s,i,o,n,s,T,y,p,e);
const XMLCh GetComplete::LOCAL_NAME[] = UNICODE_LITERAL_11(G,e,t,C,o,m,p,l,e,t,e);
const XMLCh IDPEntry::LOCAL_NAME[] = UNICODE_LITERAL_8(I,D,P,E,n,t,r,y);
const XMLCh IDPEntry::TYPE_NAME[] = UNICODE_LITERAL_12(I,D,P,E,n,t,r,y,T,y,p,e);
const XMLCh IDPEntry::PROVIDERID_ATTRIB_NAME[] = UNICODE_LITERAL_10(P,r,o,v,i,d,e,r,I,D);
const XMLCh IDPEntry::NAME_ATTRIB_NAME[] = UNICODE_LITERAL_4(N,a,m,e);
const XMLCh IDPEntry::LOC_ATTRIB_NAME[] = UNICODE_LITERAL_3(L,o,c);
const XMLCh IDPList::LOCAL_NAME[] = UNICODE_LITERAL_7(I,D,P,L,i,s,t);
const XMLCh IDPList::TYPE_NAME[] = UNICODE_LITERAL_11(I,D,P,L,i,s,t,T,y,p,e);
const XMLCh LogoutRequest::LOCAL_NAME[] = UNICODE_LITERAL_13(L,o,g,o,u,t,R,e,q,u,e,s,t);
const XMLCh LogoutRequest::TYPE_NAME[] = UNICODE_LITERAL_17(L,o,g,o,u,t,R,e,q,u,e,s,t,T,y,p,e);
const XMLCh LogoutRequest::REASON_ATTRIB_NAME[] = UNICODE_LITERAL_6(R,e,a,s,o,n);
const XMLCh LogoutRequest::NOTONORAFTER_ATTRIB_NAME[] = UNICODE_LITERAL_12(N,o,t,O,n,O,r,A,f,t,e,r);
const XMLCh LogoutResponse::LOCAL_NAME[] = UNICODE_LITERAL_14(L,o,g,o,u,t,R,e,s,p,o,n,s,e);
const XMLCh ManageNameIDRequest::LOCAL_NAME[] = UNICODE_LITERAL_19(M,a,n,a,g,e,N,a,m,e,I,D,R,e,q,u,e,s,t);
const XMLCh ManageNameIDRequest::TYPE_NAME[] = UNICODE_LITERAL_23(M,a,n,a,g,e,N,a,m,e,I,D,R,e,q,u,e,s,t,T,y,p,e);
const XMLCh ManageNameIDResponse::LOCAL_NAME[] = UNICODE_LITERAL_20(M,a,n,a,g,e,N,a,m,e,I,D,R,e,s,p,o,n,s,e);
const XMLCh NameIDMappingRequest::LOCAL_NAME[] = UNICODE_LITERAL_20(N,a,m,e,I,D,M,a,p,p,i,n,g,R,e,q,u,e,s,t);
const XMLCh NameIDMappingRequest::TYPE_NAME[] = UNICODE_LITERAL_24(N,a,m,e,I,D,M,a,p,p,i,n,g,R,e,q,u,e,s,t,T,y,p,e);
const XMLCh NameIDMappingResponse::LOCAL_NAME[] = UNICODE_LITERAL_21(N,a,m,e,I,D,M,a,p,p,i,n,g,R,e,s,p,o,n,s,e);
const XMLCh NameIDMappingResponse::TYPE_NAME[] = UNICODE_LITERAL_25(N,a,m,e,I,D,M,a,p,p,i,n,g,R,e,s,p,o,n,s,e,T,y,p,e);
const XMLCh NameIDPolicy::LOCAL_NAME[] = UNICODE_LITERAL_12(N,a,m,e,I,D,P,o,l,i,c,y);
const XMLCh NameIDPolicy::TYPE_NAME[] = UNICODE_LITERAL_16(N,a,m,e,I,D,P,o,l,i,c,y,T,y,p,e);
const XMLCh NameIDPolicy::FORMAT_ATTRIB_NAME[] = UNICODE_LITERAL_6(F,o,r,m,a,t);
const XMLCh NameIDPolicy::SPNAMEQUALIFIER_ATTRIB_NAME[] = UNICODE_LITERAL_15(S,P,N,a,m,e,Q,u,a,l,i,f,i,e,r);
const XMLCh NameIDPolicy::ALLOWCREATE_ATTRIB_NAME[] = UNICODE_LITERAL_11(A,l,l,o,w,C,r,e,a,t,e);
const XMLCh NewEncryptedID::LOCAL_NAME[] = UNICODE_LITERAL_14(N,e,w,E,n,c,r,y,p,t,e,d,I,D);
const XMLCh NewID::LOCAL_NAME[] = UNICODE_LITERAL_5(N,e,w,I,D);
const XMLCh RequesterID::LOCAL_NAME[] = UNICODE_LITERAL_11(R,e,q,u,e,s,t,e,r,I,D);
const XMLCh RequestedAuthnContext::LOCAL_NAME[] = UNICODE_LITERAL_21(R,e,q,u,e,s,t,e,d,A,u,t,h,n,C,o,n,t,e,x,t);
const XMLCh RequestedAuthnContext::TYPE_NAME[] = UNICODE_LITERAL_25(R,e,q,u,e,s,t,e,d,A,u,t,h,n,C,o,n,t,e,x,t,T,y,p,e);
const XMLCh RequestedAuthnContext::COMPARISON_ATTRIB_NAME[] = UNICODE_LITERAL_10(C,o,m,p,a,r,i,s,o,n);
const XMLCh RequestedAuthnContext::COMPARISON_EXACT[] = UNICODE_LITERAL_5(e,x,a,c,t);
const XMLCh RequestedAuthnContext::COMPARISON_MINIMUM[] = UNICODE_LITERAL_7(m,i,n,i,m,u,m);
const XMLCh RequestedAuthnContext::COMPARISON_MAXIMUM[] = UNICODE_LITERAL_7(m,a,x,i,m,u,m);
const XMLCh RequestedAuthnContext::COMPARISON_BETTER[] = UNICODE_LITERAL_6(b,e,t,t,e,r);
const XMLCh RequestAbstractType::LOCAL_NAME[] = {chNull};
const XMLCh RequestAbstractType::TYPE_NAME[] = UNICODE_LITERAL_19(R,e,q,u,e,s,t,A,b,s,t,r,a,c,t,T,y,p,e);
const XMLCh RequestAbstractType::ID_ATTRIB_NAME[] = UNICODE_LITERAL_2(I,D);
const XMLCh RequestAbstractType::VER_ATTRIB_NAME[] = UNICODE_LITERAL_7(V,e,r,s,i,o,n);
const XMLCh RequestAbstractType::ISSUEINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_12(I,s,s,u,e,I,n,s,t,a,n,t);
const XMLCh RequestAbstractType::DESTINATION_ATTRIB_NAME[] = UNICODE_LITERAL_11(D,e,s,t,i,n,a,t,i,o,n);
const XMLCh RequestAbstractType::CONSENT_ATTRIB_NAME[] = UNICODE_LITERAL_7(C,o,n,s,e,n,t);
const XMLCh RespondTo::LOCAL_NAME[] = UNICODE_LITERAL_9(R,e,s,p,o,n,d,T,o);
const XMLCh Response::LOCAL_NAME[] = UNICODE_LITERAL_8(R,e,s,p,o,n,s,e);
const XMLCh Response::TYPE_NAME[] = UNICODE_LITERAL_12(R,e,s,p,o,n,s,e,T,y,p,e);
const XMLCh Scoping::LOCAL_NAME[] = UNICODE_LITERAL_7(S,c,o,p,i,n,g);
const XMLCh Scoping::TYPE_NAME[] = UNICODE_LITERAL_11(S,c,o,p,i,n,g,T,y,p,e);
const XMLCh Scoping::PROXYCOUNT_ATTRIB_NAME[] = UNICODE_LITERAL_10(P,r,o,x,y,C,o,u,n,t);
const XMLCh SessionIndex::LOCAL_NAME[] = UNICODE_LITERAL_12(S,e,s,s,i,o,n,I,n,d,e,x);
const XMLCh Status::LOCAL_NAME[] = UNICODE_LITERAL_6(S,t,a,t,u,s);
const XMLCh Status::TYPE_NAME[] = UNICODE_LITERAL_10(S,t,a,t,u,s,T,y,p,e);
const XMLCh StatusCode::LOCAL_NAME[] = UNICODE_LITERAL_10(S,t,a,t,u,s,C,o,d,e);
const XMLCh StatusCode::TYPE_NAME[] = UNICODE_LITERAL_14(S,t,a,t,u,s,C,o,d,e,T,y,p,e);
const XMLCh StatusCode::VALUE_ATTRIB_NAME[] = UNICODE_LITERAL_5(V,a,l,u,e);
const XMLCh StatusDetail::LOCAL_NAME[] = UNICODE_LITERAL_12(S,t,a,t,u,s,D,e,t,a,i,l);
const XMLCh StatusDetail::TYPE_NAME[] = UNICODE_LITERAL_16(S,t,a,t,u,s,D,e,t,a,i,l,T,y,p,e);
const XMLCh StatusMessage::LOCAL_NAME[] = UNICODE_LITERAL_13(S,t,a,t,u,s,M,e,s,s,a,g,e);
const XMLCh StatusResponseType::LOCAL_NAME[] = {chNull};
const XMLCh StatusResponseType::TYPE_NAME[] = UNICODE_LITERAL_18(S,t,a,t,u,s,R,e,s,p,o,n,s,e,T,y,p,e);
const XMLCh StatusResponseType::ID_ATTRIB_NAME[] = UNICODE_LITERAL_2(I,D);
const XMLCh StatusResponseType::INRESPONSETO_ATTRIB_NAME[] = UNICODE_LITERAL_12(I,n,R,e,s,p,o,n,s,e,T,o);
const XMLCh StatusResponseType::VER_ATTRIB_NAME[] = UNICODE_LITERAL_7(V,e,r,s,i,o,n);
const XMLCh StatusResponseType::ISSUEINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_12(I,s,s,u,e,I,n,s,t,a,n,t);
const XMLCh StatusResponseType::DESTINATION_ATTRIB_NAME[] = UNICODE_LITERAL_11(D,e,s,t,i,n,a,t,i,o,n);
const XMLCh StatusResponseType::CONSENT_ATTRIB_NAME[] = UNICODE_LITERAL_7(C,o,n,s,e,n,t);
const XMLCh SubjectQuery::LOCAL_NAME[] = UNICODE_LITERAL_12(S,u,b,j,e,c,t,Q,u,e,r,y);
const XMLCh SubjectQuery::TYPE_NAME[] = UNICODE_LITERAL_24(S,u,b,j,e,c,t,Q,u,e,r,y,A,b,s,t,r,a,c,t,T,y,p,e);
const XMLCh Terminate::LOCAL_NAME[] = UNICODE_LITERAL_9(T,e,r,m,i,n,a,t,e);
const XMLCh Terminate::TYPE_NAME[] = UNICODE_LITERAL_13(T,e,r,m,i,n,a,t,e,T,y,p,e);

// Unicode literals: LogoutRequest element, Reason attribute
const XMLCh LogoutRequest::REASON_USER[] = // urn:oasis:names:tc:SAML:2.0:logout:user
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_l, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t, chColon,
  chLatin_u, chLatin_s, chLatin_e, chLatin_r, chNull
};

const XMLCh LogoutRequest::REASON_ADMIN[] = // urn:oasis:names:tc:SAML:2.0:logout:admin
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_l, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t, chColon,
  chLatin_a, chLatin_d, chLatin_m, chLatin_i, chLatin_n, chNull
};


const XMLCh LogoutRequest::REASON_GLOBAL_TIMEOUT[] = // urn:oasis:names:tc:SAML:2.0:logout:global-timeout
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_l, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t, chColon,
  chLatin_g, chLatin_l, chLatin_o, chLatin_b, chLatin_a, chLatin_l, 
    chDash, chLatin_t, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull
};


const XMLCh LogoutRequest::REASON_SP_TIMEOUT[] = // urn:oasis:names:tc:SAML:2.0:logout:sp-timeout
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_l, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t, chColon,
  chLatin_s, chLatin_p, chDash, chLatin_t, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull
};


// Unicode literals, StatusCode Value
const XMLCh StatusCode::SUCCESS[] = //  urn:oasis:names:tc:SAML:2.0:status:Success 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_S, chLatin_u, chLatin_c, chLatin_c, chLatin_e, chLatin_s, chLatin_s, chNull
};

const XMLCh StatusCode::REQUESTER[] = //  urn:oasis:names:tc:SAML:2.0:status:Requester 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_e, chLatin_r, chNull
};

const XMLCh StatusCode::RESPONDER[] = //  urn:oasis:names:tc:SAML:2.0:status:Responder 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_R, chLatin_e, chLatin_s, chLatin_p, chLatin_o, chLatin_n, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh StatusCode::VERSION_MISMATCH[] = //  urn:oasis:names:tc:SAML:2.0:status:VersionMismatch 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_V, chLatin_e, chLatin_r, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
    chLatin_M, chLatin_i, chLatin_s, chLatin_m, chLatin_a, chLatin_t, chLatin_c, chLatin_h, chNull
};

const XMLCh StatusCode::AUTHN_FAILED[] = //  urn:oasis:names:tc:SAML:2.0:status:AuthnFailed 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n,
    chLatin_F, chLatin_a, chLatin_i, chLatin_l, chLatin_e, chLatin_d, chNull
};

const XMLCh StatusCode::INVALID_ATTR_NAME_OR_VALUE[] = //  urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_I, chLatin_n, chLatin_v, chLatin_a, chLatin_l, chLatin_i, chLatin_d, 
    chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_N, chLatin_a, chLatin_m, chLatin_e, 
    chLatin_O, chLatin_r, chLatin_V, chLatin_a, chLatin_l, chLatin_u, chLatin_e, chNull
};

const XMLCh StatusCode::INVALID_NAMEID_POLICY[] = //  urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_I, chLatin_n, chLatin_v, chLatin_a, chLatin_l, chLatin_i, chLatin_d, 
   chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_I, chLatin_D, 
   chLatin_P, chLatin_o, chLatin_l, chLatin_i, chLatin_c, chLatin_y, chNull
};

const XMLCh StatusCode::NO_AUTHN_CONTEXT[] = //  urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_N, chLatin_o, chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n, 
  chLatin_C, chLatin_o, chLatin_n, chLatin_t, chLatin_e, chLatin_x, chLatin_t, chNull
};

const XMLCh StatusCode::NO_AVAILABLE_IDP[] = //  urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_N, chLatin_o, chLatin_A, chLatin_v, chLatin_a, chLatin_i, chLatin_l, chLatin_a, chLatin_b, chLatin_l, chLatin_e, 
   chLatin_I, chLatin_D, chLatin_P, chNull
};

const XMLCh StatusCode::NO_PASSIVE[] = //  urn:oasis:names:tc:SAML:2.0:status:NoPassive 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_N, chLatin_o, chLatin_P, chLatin_a, chLatin_s, chLatin_s, chLatin_i, chLatin_v, chLatin_e, chNull
};

const XMLCh StatusCode::NO_SUPPORTED_IDP[] = //  urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_N, chLatin_o, chLatin_S, chLatin_u, chLatin_p, chLatin_p, chLatin_o, chLatin_r, chLatin_t, chLatin_e, chLatin_d,
      chLatin_I, chLatin_D, chLatin_P, chNull
};

const XMLCh StatusCode::PARTIAL_LOGOUT[] = //  urn:oasis:names:tc:SAML:2.0:status:PartialLogout 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_P, chLatin_a, chLatin_r, chLatin_t, chLatin_i, chLatin_a, chLatin_l, 
    chLatin_L, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t, chNull
};

const XMLCh StatusCode::PROXY_COUNT_EXCEEDED[] = //  urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_P, chLatin_r, chLatin_o, chLatin_x, chLatin_y, chLatin_C, chLatin_o, chLatin_u, chLatin_n, chLatin_t, 
    chLatin_E, chLatin_x, chLatin_c, chLatin_e, chLatin_e, chLatin_d, chLatin_e, chLatin_d, chNull
};

const XMLCh StatusCode::REQUEST_DENIED[] = //  urn:oasis:names:tc:SAML:2.0:status:RequestDenied 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, 
    chLatin_D, chLatin_e, chLatin_n, chLatin_i, chLatin_e, chLatin_d, chNull
};

const XMLCh StatusCode::REQUEST_UNSUPPORTED[] = //  urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, 
    chLatin_U, chLatin_n, chLatin_s, chLatin_u, chLatin_p, chLatin_p, chLatin_o, chLatin_r, chLatin_t, chLatin_e, chLatin_d, chNull
};

const XMLCh StatusCode::REQUEST_VERSION_DEPRECATED[] = //  urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, 
    chLatin_V, chLatin_e, chLatin_r, chLatin_s, chLatin_i, chLatin_o, chLatin_n, 
    chLatin_D, chLatin_e, chLatin_p, chLatin_r, chLatin_e, chLatin_c, chLatin_a, chLatin_t, chLatin_e, chLatin_d, chNull
};

const XMLCh StatusCode::REQUEST_VERSION_TOO_HIGH[] = //  urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, 
  chLatin_V, chLatin_e, chLatin_r, chLatin_s, chLatin_i, chLatin_o, chLatin_n, 
  chLatin_T, chLatin_o, chLatin_o, chLatin_H, chLatin_i, chLatin_g, chLatin_h, chNull
};

const XMLCh StatusCode::REQUEST_VERSION_TOO_LOW[] = //  urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, 
    chLatin_V, chLatin_e, chLatin_r, chLatin_s, chLatin_i, chLatin_o, chLatin_n, 
    chLatin_T, chLatin_o, chLatin_o, chLatin_L, chLatin_o, chLatin_w, chNull
};

const XMLCh StatusCode::RESOURCE_NOT_RECOGNIZED[] = //  urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_u, chLatin_r, chLatin_c, chLatin_e, 
    chLatin_N, chLatin_o, chLatin_t, 
    chLatin_R, chLatin_e, chLatin_c, chLatin_o, chLatin_g, chLatin_n, chLatin_i, chLatin_z, chLatin_e, chLatin_d, chNull
};

const XMLCh StatusCode::TOO_MANY_RESPONSES[] = //  urn:oasis:names:tc:SAML:2.0:status:TooManyResponses 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_T, chLatin_o, chLatin_o, chLatin_M, chLatin_a, chLatin_n, chLatin_y, 
    chLatin_R, chLatin_e, chLatin_s, chLatin_p, chLatin_o, chLatin_n, chLatin_s, chLatin_e, chLatin_s, chNull
};

const XMLCh StatusCode::UNKNOWN_ATTR_PROFILE[] = //  urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_U, chLatin_n, chLatin_k, chLatin_n, chLatin_o, chLatin_w, chLatin_n, 
    chLatin_A, chLatin_t, chLatin_t, chLatin_r, 
    chLatin_P, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chNull
};

const XMLCh StatusCode::UNKNOWN_PRINCIPAL[] = //  urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_U, chLatin_n, chLatin_k, chLatin_n, chLatin_o, chLatin_w, chLatin_n, 
    chLatin_P, chLatin_r, chLatin_i, chLatin_n, chLatin_c, chLatin_i, chLatin_p, chLatin_a, chLatin_l, chNull
};

const XMLCh StatusCode::UNSUPPORTED_BINDING[] = //  urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding 
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_s, chLatin_t, chLatin_a, chLatin_t, chLatin_u, chLatin_s, chColon,
  chLatin_U, chLatin_n, chLatin_s, chLatin_u, chLatin_p, chLatin_p, chLatin_o, chLatin_r, chLatin_t, chLatin_e, chLatin_d, 
    chLatin_B, chLatin_i, chLatin_n, chLatin_d, chLatin_i, chLatin_n, chLatin_g, chNull
};

