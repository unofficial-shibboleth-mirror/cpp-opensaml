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
 * ProtocolsImpl.cpp
 * 
 * Implementation classes for SAML 1.x Protocols schema
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/core/Protocols.h"

#include <xmltooling/AbstractChildlessElement.h>
#include <xmltooling/AbstractComplexElement.h>
#include <xmltooling/AbstractElementProxy.h>
#include <xmltooling/AbstractSimpleElement.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/validation/AbstractValidatingXMLObject.h>

#include <ctime>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {
    namespace saml1 {
    
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AssertionArtifact);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,StatusMessage);

        class SAML_DLLLOCAL RespondWithImpl : public virtual RespondWith,
            protected AbstractSimpleElement,
            public AbstractChildlessElement,
            public AbstractDOMCachingXMLObject,
            public AbstractValidatingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            QName* m_qname;
        public:
            virtual ~RespondWithImpl() {
                delete m_qname;
            }
    
            RespondWithImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType), m_qname(NULL) {
            }
                
            RespondWithImpl(const RespondWithImpl& src)
                    : AbstractXMLObject(src),
                        AbstractSimpleElement(src),
                        AbstractDOMCachingXMLObject(src),
                        AbstractValidatingXMLObject(src), m_qname(NULL) {
                setQName(src.getQName());
            }
            
            QName* getQName() const {
                return m_qname;
            }
            
            void setQName(const QName* qname) {
                m_qname=prepareForAssignment(m_qname,qname);
                if (m_qname) {
                    auto_ptr_XMLCh temp(m_qname->toString().c_str());
                    setTextContent(temp.get());
                }
                else
                    setTextContent(NULL);
            }
            
            IMPL_XMLOBJECT_CLONE(RespondWith);
            IMPL_XMLOBJECT_CONTENT;
        };

        class SAML_DLLLOCAL SubjectQueryImpl : public virtual SubjectQuery,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractValidatingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Subject=NULL;
                m_children.push_back(NULL);
                m_pos_Subject=m_children.begin();
            }
        protected:
            SubjectQueryImpl() {
                init();
            }
        public:
            virtual ~SubjectQueryImpl() {}
    
            SubjectQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            SubjectQueryImpl(const SubjectQueryImpl& src)
                    : AbstractXMLObject(src),
                        AbstractDOMCachingXMLObject(src),
                        AbstractValidatingXMLObject(src) {
                init();
                if (src.getSubject())
                    setSubject(src.getSubject()->cloneSubject());
            }
            
            IMPL_TYPED_CHILD(Subject);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Subject,SAMLConstants::SAML1_NS,true);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthenticationQueryImpl : public virtual AuthenticationQuery, public SubjectQueryImpl
        {
            void init() {
                m_AuthenticationMethod=NULL;
            }
        public:
            virtual ~AuthenticationQueryImpl() {
                XMLString::release(&m_AuthenticationMethod);
            }
    
            AuthenticationQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AuthenticationQueryImpl(const AuthenticationQueryImpl& src)
                    : AbstractXMLObject(src), SubjectQueryImpl(src) {
                init();
                setAuthenticationMethod(src.getAuthenticationMethod());
            }
            
            IMPL_XMLOBJECT_CLONE(AuthenticationQuery);
            SubjectQuery* cloneSubjectQuery() const {
                return cloneAuthenticationQuery();
            }
            Query* cloneQuery() const {
                return cloneAuthenticationQuery();
            }
            IMPL_STRING_ATTRIB(AuthenticationMethod);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(AuthenticationMethod,AUTHENTICATIONMETHOD,NULL);
                SubjectQueryImpl::marshallAttributes(domElement);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(AuthenticationMethod,AUTHENTICATIONMETHOD,NULL);
                SubjectQueryImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AttributeQueryImpl : public virtual AttributeQuery, public SubjectQueryImpl
        {
            void init() {
                m_Resource=NULL;
            }
        public:
            virtual ~AttributeQueryImpl() {
                XMLString::release(&m_Resource);
            }
    
            AttributeQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AttributeQueryImpl(const AttributeQueryImpl& src)
                    : AbstractXMLObject(src), SubjectQueryImpl(src) {
                init();
                setResource(src.getResource());
                VectorOf(AttributeDesignator) v=getAttributeDesignators();
                for (vector<AttributeDesignator*>::const_iterator i=src.m_AttributeDesignators.begin(); i!=src.m_AttributeDesignators.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAttributeDesignator());
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(AttributeQuery);
            SubjectQuery* cloneSubjectQuery() const {
                return cloneAttributeQuery();
            }
            Query* cloneQuery() const {
                return cloneAttributeQuery();
            }
            IMPL_STRING_ATTRIB(Resource);
            IMPL_TYPED_CHILDREN(AttributeDesignator,m_children.end());
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Resource,RESOURCE,NULL);
                SubjectQueryImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AttributeDesignator,SAMLConstants::SAML1_NS,true);
                SubjectQueryImpl::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Resource,RESOURCE,NULL);
                SubjectQueryImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AuthorizationDecisionQueryImpl : public virtual AuthorizationDecisionQuery, public SubjectQueryImpl
        {
            void init() {
                m_Resource=NULL;
                m_Evidence=NULL;
                m_children.push_back(NULL);
                m_pos_Evidence=m_pos_Subject;
                m_pos_Evidence++;
            }
        public:
            virtual ~AuthorizationDecisionQueryImpl() {
                XMLString::release(&m_Resource);
            }
    
            AuthorizationDecisionQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AuthorizationDecisionQueryImpl(const AuthorizationDecisionQueryImpl& src)
                    : AbstractXMLObject(src), SubjectQueryImpl(src) {
                init();
                setResource(src.getResource());
                if (src.getEvidence())
                    setEvidence(src.getEvidence()->cloneEvidence());
                VectorOf(Action) v=getActions();
                for (vector<Action*>::const_iterator i=src.m_Actions.begin(); i!=src.m_Actions.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAction());
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(AuthorizationDecisionQuery);
            SubjectQuery* cloneSubjectQuery() const {
                return cloneAuthorizationDecisionQuery();
            }
            Query* cloneQuery() const {
                return cloneAuthorizationDecisionQuery();
            }
            IMPL_STRING_ATTRIB(Resource);
            IMPL_TYPED_CHILD(Evidence);
            IMPL_TYPED_CHILDREN(Action, m_pos_Evidence);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Resource,RESOURCE,NULL);
                SubjectQueryImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Evidence,SAMLConstants::SAML1_NS,false);
                PROC_TYPED_CHILDREN(Action,SAMLConstants::SAML1_NS,false);
                SubjectQueryImpl::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Resource,RESOURCE,NULL);
                SubjectQueryImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AbstractRequestImpl : public virtual AbstractRequest,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractValidatingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_MinorVersion=1;
                m_RequestID=NULL;
                m_IssueInstant=NULL;
                m_children.push_back(NULL);
                m_Signature=NULL;
                m_pos_Signature=m_children.begin();
            }
        protected:
            AbstractRequestImpl() {
                init();
            }
        public:
            virtual ~AbstractRequestImpl() {
                XMLString::release(&m_RequestID);
                delete m_IssueInstant;
            }
    
            AbstractRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AbstractRequestImpl(const AbstractRequestImpl& src)
                    : AbstractXMLObject(src),
                        AbstractDOMCachingXMLObject(src),
                        AbstractValidatingXMLObject(src) {
                init();
                setMinorVersion(src.getMinorVersion());
                setRequestID(src.getRequestID());
                setIssueInstant(src.getIssueInstant());
                if (src.getSignature())
                    setSignature(src.getSignature()->cloneSignature());
                VectorOf(RespondWith) v=getRespondWiths();
                for (vector<RespondWith*>::const_iterator i=src.m_RespondWiths.begin(); i!=src.m_RespondWiths.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneRespondWith());
                    }
                }
            }
            
            const XMLCh* getId() const {
                return getRequestID();
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

            IMPL_INTEGER_ATTRIB(MinorVersion);
            IMPL_STRING_ATTRIB(RequestID);
            IMPL_DATETIME_ATTRIB(IssueInstant);
            IMPL_TYPED_CHILDREN(RespondWith,m_pos_Signature);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                static const XMLCh MAJORVERSION[] = UNICODE_LITERAL_12(M,a,j,o,r,V,e,r,s,i,o,n);
                static const XMLCh ONE[] = { chDigit_1, chNull };
                domElement->setAttributeNS(NULL,MAJORVERSION,ONE);
                MARSHALL_INTEGER_ATTRIB(MinorVersion,MINORVERSION,NULL);
                if (!m_RequestID)
                    const_cast<AbstractRequestImpl*>(this)->m_RequestID=SAMLConfig::getConfig().generateIdentifier();
                MARSHALL_ID_ATTRIB(RequestID,REQUESTID,NULL);
                if (!m_IssueInstant)
                    const_cast<AbstractRequestImpl*>(this)->m_IssueInstant=new DateTime(time(NULL));
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(RespondWith,SAMLConstants::SAML1P_NS,false);
                PROC_TYPED_CHILD(Signature,XMLConstants::XMLSIG_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                static const XMLCh MAJORVERSION[] = UNICODE_LITERAL_12(M,a,j,o,r,V,e,r,s,i,o,n);
                if (XMLHelper::isNodeNamed(attribute,NULL,MAJORVERSION)) {
                    if (XMLString::parseInt(attribute->getValue()) != 1)
                        throw UnmarshallingException("Request has invalid major version.");
                }
                PROC_INTEGER_ATTRIB(MinorVersion,MINORVERSION,NULL);
                PROC_ID_ATTRIB(RequestID,REQUESTID,NULL);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
            }
        };

        class SAML_DLLLOCAL RequestImpl : public virtual Request, public AbstractRequestImpl
        {
            void init() {
                m_children.push_back(NULL);
                m_Query=NULL;
                m_pos_Query=m_pos_Signature;
                m_pos_Query++;
            }
        public:
            virtual ~RequestImpl() {}
    
            RequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            RequestImpl(const RequestImpl& src)
                    : AbstractXMLObject(src), AbstractRequestImpl(src) {
                init();
                if (src.getQuery())
                    setQuery(src.getQuery()->cloneQuery());
                VectorOf(AssertionIDReference) v=getAssertionIDReferences();
                for (vector<AssertionIDReference*>::const_iterator i=src.m_AssertionIDReferences.begin(); i!=src.m_AssertionIDReferences.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAssertionIDReference());
                    }
                }
                VectorOf(AssertionArtifact) v2=getAssertionArtifacts();
                for (vector<AssertionArtifact*>::const_iterator i=src.m_AssertionArtifacts.begin(); i!=src.m_AssertionArtifacts.end(); i++) {
                    if (*i) {
                        v2.push_back((*i)->cloneAssertionArtifact());
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(Request);
            AbstractRequest* cloneAbstractRequest() const {
                return cloneRequest();
            }
            IMPL_TYPED_CHILD(Query);
            
            SubjectQuery* getSubjectQuery() const {
                return dynamic_cast<SubjectQuery*>(getQuery());
            }
            AuthenticationQuery* getAuthenticationQuery() const {
                return dynamic_cast<AuthenticationQuery*>(getQuery());
            }
            AttributeQuery* getAttributeQuery() const {
                return dynamic_cast<AttributeQuery*>(getQuery());
            }
            AuthorizationDecisionQuery* getAuthorizationDecisionQuery() const {
                return dynamic_cast<AuthorizationDecisionQuery*>(getQuery());
            }

            void setSubjectQuery(SubjectQuery* q) {
                setQuery(q);
            }
            void setAuthenticationQuery(AuthenticationQuery* q) {
                setQuery(q);
            }
            void setAttributeQuery(AttributeQuery* q) {
                setQuery(q);
            }
            void setAuthorizationDecisionQuery(AuthorizationDecisionQuery* q) {
                setQuery(q);
            }
            
            IMPL_TYPED_CHILDREN(AssertionIDReference, m_children.end());
            IMPL_TYPED_CHILDREN(AssertionArtifact, m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Query,SAMLConstants::SAML1P_NS,true);
                PROC_TYPED_CHILDREN(AssertionIDReference,SAMLConstants::SAML1_NS,false);
                PROC_TYPED_CHILDREN(AssertionArtifact,SAMLConstants::SAML1P_NS,false);
                AbstractRequestImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL StatusCodeImpl : public virtual StatusCode,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractValidatingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Value=NULL;
                m_children.push_back(NULL);
                m_StatusCode=NULL;
                m_pos_StatusCode=m_children.begin();
            }
        public:
            virtual ~StatusCodeImpl() {
                delete m_Value;
            }
    
            StatusCodeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            StatusCodeImpl(const StatusCodeImpl& src)
                    : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
                init();
                setValue(src.getValue());
                if (src.getStatusCode())
                    setStatusCode(src.getStatusCode()->cloneStatusCode());
            }
            
            IMPL_XMLOBJECT_CLONE(StatusCode);
            IMPL_XMLOBJECT_ATTRIB(Value,QName);
            IMPL_TYPED_CHILD(StatusCode);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_QNAME_ATTRIB(Value,VALUE,NULL);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(StatusCode,SAMLConstants::SAML1P_NS,true);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_QNAME_ATTRIB(Value,VALUE,NULL);
            }
        };

        class SAML_DLLLOCAL StatusDetailImpl : public virtual StatusDetail,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractValidatingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~StatusDetailImpl() {}
    
            StatusDetailImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            StatusDetailImpl(const StatusDetailImpl& src)
                    : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
                VectorOf(XMLObject) v=getDetails();
                for (vector<XMLObject*>::const_iterator i=src.m_Details.begin(); i!=src.m_Details.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->clone());
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(StatusDetail);
            IMPL_XMLOBJECT_CHILDREN(Detail,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                getDetails().push_back(childXMLObject);
            }
        };

        class SAML_DLLLOCAL StatusImpl : public virtual Status,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractValidatingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_StatusCode=NULL;
                m_pos_StatusCode=m_children.begin();
                m_StatusMessage=NULL;
                m_pos_StatusMessage=m_pos_StatusCode;
                m_pos_StatusMessage++;
                m_StatusDetail=NULL;
                m_pos_StatusDetail=m_pos_StatusMessage;
                m_pos_StatusDetail++;
            }
        public:
            virtual ~StatusImpl() {}
    
            StatusImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            StatusImpl(const StatusImpl& src)
                    : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
                init();
                if (src.getStatusCode())
                    setStatusCode(src.getStatusCode()->cloneStatusCode());
                if (src.getStatusMessage())
                    setStatusMessage(src.getStatusMessage()->cloneStatusMessage());
                if (src.getStatusDetail())
                    setStatusDetail(src.getStatusDetail()->cloneStatusDetail());
            }
            
            IMPL_XMLOBJECT_CLONE(Status);
            IMPL_TYPED_CHILD(StatusCode);
            IMPL_TYPED_CHILD(StatusMessage);
            IMPL_TYPED_CHILD(StatusDetail);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(StatusCode,SAMLConstants::SAML1P_NS,false);
                PROC_TYPED_CHILD(StatusMessage,SAMLConstants::SAML1P_NS,false);
                PROC_TYPED_CHILD(StatusDetail,SAMLConstants::SAML1P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AbstractResponseImpl : public virtual AbstractResponse,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractValidatingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_MinorVersion=1;
                m_ResponseID=NULL;
                m_InResponseTo=NULL;
                m_IssueInstant=NULL;
                m_Recipient=NULL;
                m_children.push_back(NULL);
                m_Signature=NULL;
                m_pos_Signature=m_children.begin();
            }
        protected:
            AbstractResponseImpl() {
                init();
            }
        public:
            virtual ~AbstractResponseImpl() {
                XMLString::release(&m_ResponseID);
                XMLString::release(&m_InResponseTo);
                XMLString::release(&m_Recipient);
                delete m_IssueInstant;
            }
    
            AbstractResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            AbstractResponseImpl(const AbstractResponseImpl& src)
                    : AbstractXMLObject(src),
                        AbstractDOMCachingXMLObject(src),
                        AbstractValidatingXMLObject(src) {
                init();
                setMinorVersion(src.getMinorVersion());
                setResponseID(src.getResponseID());
                setInResponseTo(src.getInResponseTo());
                setIssueInstant(src.getIssueInstant());
                setRecipient(src.getRecipient());
                if (src.getSignature())
                    setSignature(src.getSignature()->cloneSignature());
            }

            const XMLCh* getId() const {
                return getResponseID();
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

            IMPL_INTEGER_ATTRIB(MinorVersion);
            IMPL_STRING_ATTRIB(ResponseID);
            IMPL_STRING_ATTRIB(InResponseTo);
            IMPL_DATETIME_ATTRIB(IssueInstant);
            IMPL_STRING_ATTRIB(Recipient);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                static const XMLCh MAJORVERSION[] = UNICODE_LITERAL_12(M,a,j,o,r,V,e,r,s,i,o,n);
                static const XMLCh ONE[] = { chDigit_1, chNull };
                domElement->setAttributeNS(NULL,MAJORVERSION,ONE);
                MARSHALL_INTEGER_ATTRIB(MinorVersion,MINORVERSION,NULL);
                if (!m_ResponseID)
                    const_cast<AbstractResponseImpl*>(this)->m_ResponseID=SAMLConfig::getConfig().generateIdentifier();
                MARSHALL_ID_ATTRIB(ResponseID,RESPONSEID,NULL);
                MARSHALL_STRING_ATTRIB(InResponseTo,INRESPONSETO,NULL);
                if (!m_IssueInstant)
                    const_cast<AbstractResponseImpl*>(this)->m_IssueInstant=new DateTime(time(NULL));
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
                MARSHALL_STRING_ATTRIB(Recipient,RECIPIENT,NULL);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Signature,XMLConstants::XMLSIG_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                static const XMLCh MAJORVERSION[] = UNICODE_LITERAL_12(M,a,j,o,r,V,e,r,s,i,o,n);
                if (XMLHelper::isNodeNamed(attribute,NULL,MAJORVERSION)) {
                    if (XMLString::parseInt(attribute->getValue()) != 1)
                        throw UnmarshallingException("Response has invalid major version.");
                }
                PROC_INTEGER_ATTRIB(MinorVersion,MINORVERSION,NULL);
                PROC_ID_ATTRIB(ResponseID,RESPONSEID,NULL);
                PROC_STRING_ATTRIB(InResponseTo,INRESPONSETO,NULL);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
                PROC_STRING_ATTRIB(Recipient,RECIPIENT,NULL);
            }
        };

        class SAML_DLLLOCAL ResponseImpl : public virtual Response, public AbstractResponseImpl
        {
            void init() {
                m_children.push_back(NULL);
                m_Status=NULL;
                m_pos_Status=m_pos_Signature;
                m_pos_Status++;
            }
        public:
            virtual ~ResponseImpl() {}
    
            ResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }
                
            ResponseImpl(const ResponseImpl& src)
                    : AbstractXMLObject(src), AbstractResponseImpl(src) {
                init();
                if (src.getStatus())
                    setStatus(src.getStatus()->cloneStatus());
                VectorOf(Assertion) v=getAssertions();
                for (vector<Assertion*>::const_iterator i=src.m_Assertions.begin(); i!=src.m_Assertions.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAssertion());
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(Response);
            AbstractResponse* cloneAbstractResponse() const {
                return cloneResponse();
            }
            IMPL_TYPED_CHILD(Status);
            IMPL_TYPED_CHILDREN(Assertion, m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Status,SAMLConstants::SAML1P_NS,false);
                PROC_TYPED_CHILDREN(Assertion,SAMLConstants::SAML1_NS,true);
                AbstractResponseImpl::processChildElement(childXMLObject,root);
            }
        };

    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

// Builder Implementations

IMPL_XMLOBJECTBUILDER(AssertionArtifact);
IMPL_XMLOBJECTBUILDER(AttributeQuery);
IMPL_XMLOBJECTBUILDER(AuthenticationQuery);
IMPL_XMLOBJECTBUILDER(AuthorizationDecisionQuery);
IMPL_XMLOBJECTBUILDER(Request);
IMPL_XMLOBJECTBUILDER(RespondWith);
IMPL_XMLOBJECTBUILDER(Response);
IMPL_XMLOBJECTBUILDER(Status);
IMPL_XMLOBJECTBUILDER(StatusCode);
IMPL_XMLOBJECTBUILDER(StatusDetail);
IMPL_XMLOBJECTBUILDER(StatusMessage);

// Unicode literals
const XMLCh AbstractRequest::MINORVERSION_ATTRIB_NAME[] =   UNICODE_LITERAL_12(M,i,n,o,r,V,e,r,s,i,o,n);
const XMLCh AbstractRequest::REQUESTID_ATTRIB_NAME[] =      UNICODE_LITERAL_9(R,e,q,u,e,s,t,I,D);
const XMLCh AbstractRequest::ISSUEINSTANT_ATTRIB_NAME[] =   UNICODE_LITERAL_12(I,s,s,u,e,I,n,s,t,a,n,t);
const XMLCh AbstractResponse::MINORVERSION_ATTRIB_NAME[] =  UNICODE_LITERAL_12(M,i,n,o,r,V,e,r,s,i,o,n);
const XMLCh AbstractResponse::RESPONSEID_ATTRIB_NAME[] =    UNICODE_LITERAL_10(R,e,s,p,o,n,s,e,I,D);
const XMLCh AbstractResponse::ISSUEINSTANT_ATTRIB_NAME[] =  UNICODE_LITERAL_12(I,s,s,u,e,I,n,s,t,a,n,t);
const XMLCh AbstractResponse::INRESPONSETO_ATTRIB_NAME[] =  UNICODE_LITERAL_12(I,n,R,e,s,p,o,n,s,e,T,o);
const XMLCh AbstractResponse::RECIPIENT_ATTRIB_NAME[] =     UNICODE_LITERAL_9(R,e,c,i,p,i,e,n,t);
const XMLCh AssertionArtifact::LOCAL_NAME[] =               UNICODE_LITERAL_17(A,s,s,e,r,t,i,o,n,A,r,t,i,f,a,c,t);
const XMLCh AttributeQuery::LOCAL_NAME[] =                  UNICODE_LITERAL_14(A,t,t,r,i,b,u,t,e,Q,u,e,r,y);
const XMLCh AttributeQuery::TYPE_NAME[] =                   UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,Q,u,e,r,y,T,y,p,e);
const XMLCh AttributeQuery::RESOURCE_ATTRIB_NAME[] =        UNICODE_LITERAL_8(R,e,s,o,u,r,c,e);
const XMLCh AuthenticationQuery::LOCAL_NAME[] =             UNICODE_LITERAL_19(A,u,t,h,e,n,t,i,c,a,t,i,o,n,Q,u,e,r,y);
const XMLCh AuthenticationQuery::TYPE_NAME[] =              UNICODE_LITERAL_23(A,u,t,h,e,n,t,i,c,a,t,i,o,n,Q,u,e,r,y,T,y,p,e);
const XMLCh AuthenticationQuery::AUTHENTICATIONMETHOD_ATTRIB_NAME[] =   UNICODE_LITERAL_20(A,u,t,h,e,n,t,i,c,a,t,i,o,n,M,e,t,h,o,d);
const XMLCh AuthorizationDecisionQuery::LOCAL_NAME[] =      UNICODE_LITERAL_26(A,u,t,h,o,r,i,z,a,t,i,o,n,D,e,c,i,s,i,o,n,Q,u,e,r,y);
const XMLCh AuthorizationDecisionQuery::TYPE_NAME[] =       UNICODE_LITERAL_30(A,u,t,h,o,r,i,z,a,t,i,o,n,D,e,c,i,s,i,o,n,Q,u,e,r,y,T,y,p,e);
const XMLCh AuthorizationDecisionQuery::RESOURCE_ATTRIB_NAME[] =        UNICODE_LITERAL_8(R,e,s,o,u,r,c,e);
const XMLCh Query::LOCAL_NAME[] =                           UNICODE_LITERAL_5(Q,u,e,r,y);
const XMLCh Request::LOCAL_NAME[] =                         UNICODE_LITERAL_7(R,e,q,u,e,s,t);
const XMLCh Request::TYPE_NAME[] =                          UNICODE_LITERAL_11(R,e,q,u,e,s,t,T,y,p,e);
const XMLCh RespondWith::LOCAL_NAME[] =                     UNICODE_LITERAL_11(R,e,s,p,o,n,d,W,i,t,h);
const XMLCh Response::LOCAL_NAME[] =                        UNICODE_LITERAL_8(R,e,s,p,o,n,s,e);
const XMLCh Response::TYPE_NAME[] =                         UNICODE_LITERAL_12(R,e,s,p,o,n,s,e,T,y,p,e);
const XMLCh Status::LOCAL_NAME[] =                          UNICODE_LITERAL_6(S,t,a,t,u,s);
const XMLCh Status::TYPE_NAME[] =                           UNICODE_LITERAL_10(S,t,a,t,u,s,T,y,p,e);
const XMLCh StatusCode::LOCAL_NAME[] =                      UNICODE_LITERAL_10(S,t,a,t,u,s,C,o,d,e);
const XMLCh StatusCode::TYPE_NAME[] =                       UNICODE_LITERAL_14(S,t,a,t,u,s,C,o,d,e,T,y,p,e);
const XMLCh StatusCode::VALUE_ATTRIB_NAME[] =               UNICODE_LITERAL_5(V,a,l,u,e);
const XMLCh StatusDetail::LOCAL_NAME[] =                    UNICODE_LITERAL_12(S,t,a,t,u,s,D,e,t,a,i,l);
const XMLCh StatusDetail::TYPE_NAME[] =                     UNICODE_LITERAL_16(S,t,a,t,u,s,D,e,t,a,i,l,T,y,p,e);
const XMLCh StatusMessage::LOCAL_NAME[] =                   UNICODE_LITERAL_13(S,t,a,t,u,s,M,e,s,s,a,g,e);
const XMLCh SubjectQuery::LOCAL_NAME[] =                    UNICODE_LITERAL_12(S,u,b,j,e,c,t,Q,u,e,r,y);

#define XCH(ch) chLatin_##ch
#define XNUM(d) chDigit_##d

const XMLCh _SUCCESS[] =                                    UNICODE_LITERAL_7(S,u,c,c,e,s,s);
const XMLCh _REQUESTER[] =                                  UNICODE_LITERAL_9(R,e,q,u,e,s,t,e,r);
const XMLCh _RESPONDER[] =                                  UNICODE_LITERAL_9(R,e,s,p,o,n,d,e,r);
const XMLCh _VERSIONMISMATCH[] =                            UNICODE_LITERAL_15(V,e,r,s,i,o,n,M,i,s,m,a,t,c,h);
 
QName StatusCode::SUCCESS(SAMLConstants::SAML1P_NS,_SUCCESS,SAMLConstants::SAML1P_PREFIX);
QName StatusCode::REQUESTER(SAMLConstants::SAML1P_NS,_REQUESTER,SAMLConstants::SAML1P_PREFIX);
QName StatusCode::RESPONDER(SAMLConstants::SAML1P_NS,_RESPONDER,SAMLConstants::SAML1P_PREFIX);
QName StatusCode::VERSIONMISMATCH(SAMLConstants::SAML1P_NS,_VERSIONMISMATCH,SAMLConstants::SAML1P_PREFIX);
