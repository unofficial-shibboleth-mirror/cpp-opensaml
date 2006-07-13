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
 * Protocols20Impl.cpp
 * 
 * Implementation classes for SAML 2.0 Protocols schema
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/encryption/EncryptedKeyResolver.h"
#include "saml2/core/Protocols.h"

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

using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmlencryption;
using namespace xmltooling;
using namespace std;

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


        //TODO need unit test for this, using objects from another namespace
        class SAML_DLLLOCAL ExtensionsImpl : public virtual Extensions,
             public AbstractElementProxy,
             public AbstractDOMCachingXMLObject,
             public AbstractXMLObjectMarshaller,
             public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~ExtensionsImpl() {}
    
            ExtensionsImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }
                
            ExtensionsImpl(const ExtensionsImpl& src)
                    : AbstractXMLObject(src), AbstractElementProxy(src), AbstractDOMCachingXMLObject(src) {
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        getXMLObjects().push_back((*i)->clone());
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(Extensions);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAMLConstants::SAML20P_NS) && nsURI && *nsURI) {
                    getXMLObjects().push_back(childXMLObject);
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
                m_Value=NULL;
                m_StatusCode=NULL;
                m_children.push_back(NULL);
                m_pos_StatusCode=m_children.begin();
            }
            public:
                virtual ~StatusCodeImpl() {}

                StatusCodeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType)
                {
                        init();
                }

                StatusCodeImpl(const StatusCodeImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                    init();
                    setValue(src.getValue());
                    if (src.getStatusCode())
                        setStatusCode(src.getStatusCode()->cloneStatusCode());
                }

                IMPL_XMLOBJECT_CLONE(StatusCode);
                IMPL_STRING_ATTRIB(Value);
                IMPL_TYPED_CHILD(StatusCode);

            protected:
                void marshallAttributes(DOMElement* domElement) const {
                    MARSHALL_STRING_ATTRIB(Value,VALUE,NULL);
                }

                void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                    PROC_TYPED_CHILD(StatusCode,SAMLConstants::SAML20P_NS,false);
                    AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
                }

                void processAttribute(const DOMAttr* attribute) {
                    PROC_STRING_ATTRIB(Value,VALUE,NULL);
                    AbstractXMLObjectUnmarshaller::processAttribute(attribute);
                }
        };

        //TODO need unit tests for non-SAML namespace children
        class SAML_DLLLOCAL StatusDetailImpl : public virtual StatusDetail,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            public:
                virtual ~StatusDetailImpl() {}

                StatusDetailImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) { }

                StatusDetailImpl(const StatusDetailImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                    AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
                }
        };


        class SAML_DLLLOCAL StatusImpl : public virtual Status,
             public AbstractComplexElement,
             public AbstractDOMCachingXMLObject,
             public AbstractXMLObjectMarshaller,
             public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_StatusCode=NULL;
                m_StatusMessage=NULL;
                m_StatusDetail=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_pos_StatusCode=m_children.begin();
                m_pos_StatusMessage=m_pos_StatusCode;
                ++m_pos_StatusMessage;
                m_pos_StatusDetail=m_pos_StatusMessage;
                ++m_pos_StatusDetail;
            }
        public:
            virtual ~StatusImpl() { }
    
            StatusImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                    init();
            }
                
            StatusImpl(const StatusImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
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
                PROC_TYPED_CHILD(StatusCode,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_CHILD(StatusMessage,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_CHILD(StatusDetail,SAMLConstants::SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
        };


        class SAML_DLLLOCAL RequestImpl : public virtual Request,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ID=NULL;
                m_Version=NULL;
                m_IssueInstant=NULL;
                m_Destination=NULL;
                m_Consent=NULL;
                m_Issuer=NULL;
                m_Signature=NULL;
                m_Extensions=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_pos_Issuer=m_children.begin();
                m_pos_Signature=m_pos_Issuer;
                ++m_pos_Signature;
                m_pos_Extensions=m_pos_Signature;
                ++m_pos_Extensions;
            }
        protected:
            RequestImpl() {
                init();
            }
        public:
            virtual ~RequestImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_Version);
                XMLString::release(&m_Destination);
                XMLString::release(&m_Consent);
                delete m_IssueInstant;
            }
    
            RequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            RequestImpl(const RequestImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                setID(src.getID());
                setVersion(src.getVersion());
                setIssueInstant(src.getIssueInstant());
                setDestination(src.getDestination());
                setConsent(src.getConsent());
                if (src.getIssuer())
                    setIssuer(src.getIssuer()->cloneIssuer());
                if (src.getSignature())
                    setSignature(src.getSignature()->cloneSignature());
                if (src.getExtensions())
                    setExtensions(src.getExtensions()->cloneExtensions());
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
            
            IMPL_XMLOBJECT_CLONE(Request);
            IMPL_STRING_ATTRIB(Version);
            IMPL_STRING_ATTRIB(ID);
            IMPL_DATETIME_ATTRIB(IssueInstant,0);
            IMPL_STRING_ATTRIB(Destination);
            IMPL_STRING_ATTRIB(Consent);
            IMPL_TYPED_FOREIGN_CHILD(Issuer,saml2);
            IMPL_TYPED_CHILD(Extensions);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                if (!m_Version)
                    const_cast<RequestImpl*>(this)->m_Version=XMLString::transcode("2.0");
                MARSHALL_STRING_ATTRIB(Version,VER,NULL);
                if (!m_ID)
                    const_cast<RequestImpl*>(this)->m_ID=SAMLConfig::getConfig().generateIdentifier();
                MARSHALL_ID_ATTRIB(ID,ID,NULL);
                if (!m_IssueInstant) {
                    const_cast<RequestImpl*>(this)->m_IssueInstantEpoch=time(NULL);
                    const_cast<RequestImpl*>(this)->m_IssueInstant=new DateTime(m_IssueInstantEpoch);
                }
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
                MARSHALL_STRING_ATTRIB(Destination,DESTINATION,NULL);
                MARSHALL_STRING_ATTRIB(Consent,CONSENT,NULL);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Issuer,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(Signature,xmlsignature,XMLConstants::XMLSIG_NS,false);
                PROC_TYPED_CHILD(Extensions,SAMLConstants::SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_ID_ATTRIB(ID,ID,NULL);
                PROC_STRING_ATTRIB(Version,VER,NULL);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
                PROC_STRING_ATTRIB(Destination,DESTINATION,NULL);
                PROC_STRING_ATTRIB(Consent,CONSENT,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };


        class SAML_DLLLOCAL AssertionIDRequestImpl : public virtual AssertionIDRequest, public RequestImpl
        {
        public:
            virtual ~AssertionIDRequestImpl() { }
    
            AssertionIDRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) { }
                
            AssertionIDRequestImpl(const AssertionIDRequestImpl& src) : AbstractXMLObject(src), RequestImpl(src) {
                VectorOf(AssertionIDRef) v=getAssertionIDRefs();
                for (vector<AssertionIDRef*>::const_iterator i=src.m_AssertionIDRefs.begin(); i!=src.m_AssertionIDRefs.end(); i++) {
                    if (*i) {                               
                        v.push_back((*i)->cloneAssertionIDRef());
                    }
                }

            }
            
            IMPL_XMLOBJECT_CLONE(AssertionIDRequest);
            IMPL_TYPED_FOREIGN_CHILDREN(AssertionIDRef,saml2,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(AssertionIDRef,saml2,SAMLConstants::SAML20_NS,false);
                RequestImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL SubjectQueryImpl : public virtual SubjectQuery, public RequestImpl
        {
            void init()
            {
                m_Subject = NULL;
                m_children.push_back(NULL);
                m_pos_Subject = m_pos_Extensions;
                ++m_pos_Subject;
            }
        protected:
            SubjectQueryImpl() {
                init();
            }
        public:
            virtual ~SubjectQueryImpl() { }
    
            SubjectQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            { 
                init();
            }
                
            SubjectQueryImpl(const SubjectQueryImpl& src) : AbstractXMLObject(src), RequestImpl(src) {
                init();
                if (src.getSubject())
                    setSubject(src.getSubject()->cloneSubject());
            }
            
            IMPL_XMLOBJECT_CLONE(SubjectQuery);
            IMPL_TYPED_FOREIGN_CHILD(Subject,saml2);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Subject,saml2,SAMLConstants::SAML20_NS,false);
                RequestImpl::processChildElement(childXMLObject,root);
            }
        };


        class SAML_DLLLOCAL RequestedAuthnContextImpl : public virtual RequestedAuthnContext,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Comparison=NULL;
            }
        public:
            virtual ~RequestedAuthnContextImpl() {
                XMLString::release(&m_Comparison);
            }
    
            RequestedAuthnContextImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            RequestedAuthnContextImpl(const RequestedAuthnContextImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                setComparison(src.getComparison());
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        AuthnContextClassRef* classref=dynamic_cast<AuthnContextClassRef*>(*i);
                        if (classref) {
                            getAuthnContextClassRefs().push_back(classref->cloneAuthnContextClassRef());
                            continue;
                        }

                        AuthnContextDeclRef* declref=dynamic_cast<AuthnContextDeclRef*>(*i);
                        if (declref) {
                            getAuthnContextDeclRefs().push_back(declref->cloneAuthnContextDeclRef());
                            continue;
                        }
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(RequestedAuthnContext);
            IMPL_STRING_ATTRIB(Comparison);
            IMPL_TYPED_FOREIGN_CHILDREN(AuthnContextClassRef,saml2,m_children.end());
            IMPL_TYPED_FOREIGN_CHILDREN(AuthnContextDeclRef,saml2,m_children.end());
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Comparison,COMPARISON,NULL);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(AuthnContextClassRef,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(AuthnContextDeclRef,saml2,SAMLConstants::SAML20_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Comparison,COMPARISON,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };


        class SAML_DLLLOCAL AuthnQueryImpl : public virtual AuthnQuery, public SubjectQueryImpl
        {
            void init() {
                m_SessionIndex=NULL;
                m_RequestedAuthnContext=NULL;
                m_children.push_back(NULL);
                m_pos_RequestedAuthnContext = m_pos_Subject;
                ++m_pos_RequestedAuthnContext;
                
            }
        public:
            virtual ~AuthnQueryImpl() {
                XMLString::release(&m_SessionIndex);
            }
    
            AuthnQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            AuthnQueryImpl(const AuthnQueryImpl& src) : AbstractXMLObject(src), SubjectQueryImpl(src) {
                init();
                setSessionIndex(src.getSessionIndex());
                if (src.getRequestedAuthnContext())
                    setRequestedAuthnContext(src.getRequestedAuthnContext()->cloneRequestedAuthnContext());
            }
            
            IMPL_XMLOBJECT_CLONE(AuthnQuery);
            IMPL_STRING_ATTRIB(SessionIndex);
            IMPL_TYPED_CHILD(RequestedAuthnContext);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(SessionIndex,SESSIONINDEX,NULL);
                SubjectQueryImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(RequestedAuthnContext,SAMLConstants::SAML20P_NS,false);
                SubjectQueryImpl::processChildElement(childXMLObject,root);
            }
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(SessionIndex,SESSIONINDEX,NULL);
                SubjectQueryImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AttributeQueryImpl : public virtual AttributeQuery, public SubjectQueryImpl
        {
        public:
            virtual ~AttributeQueryImpl() { }
    
            AttributeQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) { }
                
            AttributeQueryImpl(const AttributeQueryImpl& src) : AbstractXMLObject(src), SubjectQueryImpl(src) {
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        Attribute* attrib=dynamic_cast<Attribute*>(*i);
                        if (attrib) {
                            getAttributes().push_back(attrib->cloneAttribute());
                            continue;
                        }
                    }
                }

            }
            
            IMPL_XMLOBJECT_CLONE(AttributeQuery);
            IMPL_TYPED_FOREIGN_CHILDREN(Attribute,saml2,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(Attribute,saml2,SAMLConstants::SAML20_NS,false);
                SubjectQueryImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthzDecisionQueryImpl : public virtual AuthzDecisionQuery, public SubjectQueryImpl
        {
            void init() {
                m_Resource=NULL;
                m_Evidence=NULL;
                m_children.push_back(NULL);
                m_pos_Evidence=m_pos_Subject;
                ++m_pos_Evidence;
                
            }
        public:
            virtual ~AuthzDecisionQueryImpl() {
                XMLString::release(&m_Resource);
            }
    
            AuthzDecisionQueryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            AuthzDecisionQueryImpl(const AuthzDecisionQueryImpl& src) : AbstractXMLObject(src), SubjectQueryImpl(src) {
                init();
                setResource(src.getResource());
                if (src.getEvidence())
                    setEvidence(src.getEvidence()->cloneEvidence());
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        Action* action=dynamic_cast<Action*>(*i);
                        if (action) {
                            getActions().push_back(action->cloneAction());
                            continue;
                        }
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(AuthzDecisionQuery);
            IMPL_STRING_ATTRIB(Resource);
            IMPL_TYPED_FOREIGN_CHILDREN(Action,saml2,m_pos_Evidence);
            IMPL_TYPED_FOREIGN_CHILD(Evidence,saml2);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Resource,RESOURCE,NULL);
                SubjectQueryImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Evidence,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(Action,saml2,SAMLConstants::SAML20_NS,false);
                SubjectQueryImpl::processChildElement(childXMLObject,root);
            }
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Resource,RESOURCE,NULL);
                SubjectQueryImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL NameIDPolicyImpl : public virtual NameIDPolicy,
            public AbstractChildlessElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Format=NULL;
                m_SPNameQualifier=NULL;
                m_AllowCreate=XMLConstants::XML_BOOL_NULL;
            }
            public:
                virtual ~NameIDPolicyImpl()
                {
                    XMLString::release(&m_Format);
                    XMLString::release(&m_SPNameQualifier);
                }

                NameIDPolicyImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType)
                {
                        init();
                }

                NameIDPolicyImpl(const NameIDPolicyImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                    init();
                    setFormat(src.getFormat());
                    setSPNameQualifier(src.getSPNameQualifier());
                    AllowCreate(m_AllowCreate);
                }

                IMPL_XMLOBJECT_CLONE(NameIDPolicy);
                IMPL_STRING_ATTRIB(Format);
                IMPL_STRING_ATTRIB(SPNameQualifier);
                IMPL_BOOLEAN_ATTRIB(AllowCreate);

            protected:
                void marshallAttributes(DOMElement* domElement) const {
                    MARSHALL_STRING_ATTRIB(Format,FORMAT,NULL);
                    MARSHALL_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER,NULL);
                    MARSHALL_BOOLEAN_ATTRIB(AllowCreate,ALLOWCREATE,NULL);
                }

                void processAttribute(const DOMAttr* attribute) {
                    PROC_STRING_ATTRIB(Format,FORMAT,NULL);
                    PROC_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER,NULL);
                    PROC_BOOLEAN_ATTRIB(AllowCreate,ALLOWCREATE,NULL);
                    AbstractXMLObjectUnmarshaller::processAttribute(attribute);
                }
        };

        class SAML_DLLLOCAL IDPEntryImpl : public virtual IDPEntry,
            public AbstractChildlessElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ProviderID=NULL;
                m_Name=NULL;
                m_Loc=NULL;
            }
            public:
                virtual ~IDPEntryImpl()
                {
                    XMLString::release(&m_ProviderID);
                    XMLString::release(&m_Name);
                    XMLString::release(&m_Loc);
                }

                IDPEntryImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType)
                {
                        init();
                }

                IDPEntryImpl(const IDPEntryImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                    init();
                    setProviderID(src.getProviderID());
                    setName(src.getName());
                    setLoc(src.getLoc());
                }

                IMPL_XMLOBJECT_CLONE(IDPEntry);
                IMPL_STRING_ATTRIB(ProviderID);
                IMPL_STRING_ATTRIB(Name);
                IMPL_STRING_ATTRIB(Loc);

            protected:
                void marshallAttributes(DOMElement* domElement) const {
                    MARSHALL_STRING_ATTRIB(ProviderID,PROVIDERID,NULL);
                    MARSHALL_STRING_ATTRIB(Name,NAME,NULL);
                    MARSHALL_STRING_ATTRIB(Loc,LOC,NULL);
                }

                void processAttribute(const DOMAttr* attribute) {
                    PROC_STRING_ATTRIB(ProviderID,PROVIDERID,NULL);
                    PROC_STRING_ATTRIB(Name,NAME,NULL);
                    PROC_STRING_ATTRIB(Loc,LOC,NULL);
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
                m_GetComplete=NULL;
                m_children.push_back(NULL);
                m_pos_GetComplete=m_children.begin();
                
            }
        public:
            virtual ~IDPListImpl() { }
    
            IDPListImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            IDPListImpl(const IDPListImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                if (src.getGetComplete())
                    setGetComplete(src.getGetComplete()->cloneGetComplete());
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        IDPEntry* entry=dynamic_cast<IDPEntry*>(*i);
                        if (entry) {
                            getIDPEntrys().push_back(entry->cloneIDPEntry());
                            continue;
                        }
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(IDPList);
            IMPL_TYPED_CHILDREN(IDPEntry,m_pos_GetComplete);
            IMPL_TYPED_CHILD(GetComplete);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(IDPEntry,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_CHILD(GetComplete,SAMLConstants::SAML20P_NS,false);
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
                m_ProxyCount=NULL;
                m_IDPList=NULL;
                m_children.push_back(NULL);
                m_pos_IDPList=m_children.begin();
                
            }
        public:
            virtual ~ScopingImpl() {
                XMLString::release(&m_ProxyCount); 
            }
    
            ScopingImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            ScopingImpl(const ScopingImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setProxyCount(m_ProxyCount);
                if (src.getIDPList())
                    setIDPList(src.getIDPList()->cloneIDPList());
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        RequesterID* reqid =dynamic_cast<RequesterID*>(*i);
                        if (reqid) {
                            getRequesterIDs().push_back(reqid->cloneRequesterID());
                            continue;
                        }
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(Scoping);
            IMPL_INTEGER_ATTRIB(ProxyCount);
            IMPL_TYPED_CHILD(IDPList);
            IMPL_TYPED_CHILDREN(RequesterID,m_children.end());
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                    MARSHALL_INTEGER_ATTRIB(ProxyCount,PROXYCOUNT,NULL);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(IDPList,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_CHILDREN(RequesterID,SAMLConstants::SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_INTEGER_ATTRIB(ProxyCount,PROXYCOUNT,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AuthnRequestImpl : public virtual AuthnRequest, public RequestImpl
        {
            void init() {
                m_ForceAuthn=XMLConstants::XML_BOOL_NULL;
                m_IsPassive=XMLConstants::XML_BOOL_NULL;
                m_ProtocolBinding=NULL;
                m_AssertionConsumerServiceIndex=NULL;
                m_AssertionConsumerServiceURL=NULL;
                m_AttributeConsumingServiceIndex=NULL;
                m_ProviderName=NULL;

                m_Subject=NULL;
                m_NameIDPolicy=NULL;
                m_Conditions=NULL;
                m_RequestedAuthnContext=NULL;
                m_Scoping=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
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
    
            AuthnRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            AuthnRequestImpl(const AuthnRequestImpl& src) : AbstractXMLObject(src), RequestImpl(src) {
                init();

                ForceAuthn(m_ForceAuthn);
                IsPassive(m_IsPassive);
                setProtocolBinding(src.getProtocolBinding());
                setAssertionConsumerServiceIndex(m_AssertionConsumerServiceIndex);
                setAssertionConsumerServiceURL(src.getAssertionConsumerServiceURL());
                setAttributeConsumingServiceIndex(m_AttributeConsumingServiceIndex);
                setProviderName(src.getProviderName());

                if (src.getSubject())
                    setSubject(src.getSubject()->cloneSubject());
                if (src.getNameIDPolicy())
                    setNameIDPolicy(src.getNameIDPolicy()->cloneNameIDPolicy());
                if (src.getConditions())
                    setConditions(src.getConditions()->cloneConditions());
                if (src.getRequestedAuthnContext())
                    setRequestedAuthnContext(src.getRequestedAuthnContext()->cloneRequestedAuthnContext());
                if (src.getScoping())
                    setScoping(src.getScoping()->cloneScoping());
            }
            
            IMPL_XMLOBJECT_CLONE(AuthnRequest);

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
                MARSHALL_BOOLEAN_ATTRIB(ForceAuthn,FORCEAUTHN,NULL);
                MARSHALL_BOOLEAN_ATTRIB(IsPassive,ISPASSIVE,NULL);
                MARSHALL_STRING_ATTRIB(ProtocolBinding,PROTOCOLBINDING,NULL);
                MARSHALL_INTEGER_ATTRIB(AssertionConsumerServiceIndex,ASSERTIONCONSUMERSERVICEINDEX,NULL);
                MARSHALL_STRING_ATTRIB(AssertionConsumerServiceURL,ASSERTIONCONSUMERSERVICEURL,NULL);
                MARSHALL_INTEGER_ATTRIB(AttributeConsumingServiceIndex,ATTRIBUTECONSUMINGSERVICEINDEX,NULL);
                MARSHALL_STRING_ATTRIB(ProviderName,PROVIDERNAME,NULL);
                RequestImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Subject,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(NameIDPolicy,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_FOREIGN_CHILD(Conditions,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(RequestedAuthnContext,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_CHILD(Scoping,SAMLConstants::SAML20P_NS,false);
                RequestImpl::processChildElement(childXMLObject,root);
            }
            void processAttribute(const DOMAttr* attribute) {
                PROC_BOOLEAN_ATTRIB(ForceAuthn,FORCEAUTHN,NULL);
                PROC_BOOLEAN_ATTRIB(IsPassive,ISPASSIVE,NULL);
                PROC_STRING_ATTRIB(ProtocolBinding,PROTOCOLBINDING,NULL);
                PROC_INTEGER_ATTRIB(AssertionConsumerServiceIndex,ASSERTIONCONSUMERSERVICEINDEX,NULL);
                PROC_STRING_ATTRIB(AssertionConsumerServiceURL,ASSERTIONCONSUMERSERVICEURL,NULL);
                PROC_INTEGER_ATTRIB(AttributeConsumingServiceIndex,ATTRIBUTECONSUMINGSERVICEINDEX,NULL);
                PROC_STRING_ATTRIB(ProviderName,PROVIDERNAME,NULL);
                RequestImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL StatusResponseImpl : public virtual StatusResponse,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_ID=NULL;
                m_InResponseTo=NULL;
                m_Version=NULL;
                m_IssueInstant=NULL;
                m_Destination=NULL;
                m_Consent=NULL;
                m_Issuer=NULL;
                m_Signature=NULL;
                m_Extensions=NULL;
                m_Status=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_pos_Issuer=m_children.begin();
                m_pos_Signature=m_pos_Issuer;
                ++m_pos_Signature;
                m_pos_Extensions=m_pos_Signature;
                ++m_pos_Extensions;
                m_pos_Status=m_pos_Extensions;
                ++m_pos_Status;
            }
        protected:
            StatusResponseImpl() {
                init();
            }
        public:
            virtual ~StatusResponseImpl() {
                XMLString::release(&m_ID);
                XMLString::release(&m_InResponseTo);
                XMLString::release(&m_Version);
                XMLString::release(&m_Destination);
                XMLString::release(&m_Consent);
                delete m_IssueInstant;
            }
    
            StatusResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            StatusResponseImpl(const StatusResponseImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                setID(src.getID());
                setInResponseTo(src.getInResponseTo());
                setVersion(src.getVersion());
                setIssueInstant(src.getIssueInstant());
                setDestination(src.getDestination());
                setConsent(src.getConsent());
                if (src.getIssuer())
                    setIssuer(src.getIssuer()->cloneIssuer());
                if (src.getSignature())
                    setSignature(src.getSignature()->cloneSignature());
                if (src.getExtensions())
                    setExtensions(src.getExtensions()->cloneExtensions());
                if (src.getStatus())
                    setStatus(src.getStatus()->cloneStatus());
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
            
            IMPL_XMLOBJECT_CLONE(StatusResponse);
            IMPL_STRING_ATTRIB(Version);
            IMPL_STRING_ATTRIB(ID);
            IMPL_STRING_ATTRIB(InResponseTo);
            IMPL_DATETIME_ATTRIB(IssueInstant,0);
            IMPL_STRING_ATTRIB(Destination);
            IMPL_STRING_ATTRIB(Consent);
            IMPL_TYPED_FOREIGN_CHILD(Issuer,saml2);
            IMPL_TYPED_CHILD(Extensions);
            IMPL_TYPED_CHILD(Status);
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                if (!m_Version)
                    const_cast<StatusResponseImpl*>(this)->m_Version=XMLString::transcode("2.0");
                MARSHALL_STRING_ATTRIB(Version,VER,NULL);
                if (!m_ID)
                    const_cast<StatusResponseImpl*>(this)->m_ID=SAMLConfig::getConfig().generateIdentifier();
                MARSHALL_ID_ATTRIB(ID,ID,NULL);
                if (!m_IssueInstant) {
                    const_cast<StatusResponseImpl*>(this)->m_IssueInstantEpoch=time(NULL);
                    const_cast<StatusResponseImpl*>(this)->m_IssueInstant=new DateTime(m_IssueInstantEpoch);
                }
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
                MARSHALL_STRING_ATTRIB(Destination,DESTINATION,NULL);
                MARSHALL_STRING_ATTRIB(Consent,CONSENT,NULL);
                MARSHALL_STRING_ATTRIB(InResponseTo,INRESPONSETO,NULL);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(Issuer,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(Signature,xmlsignature,XMLConstants::XMLSIG_NS,false);
                PROC_TYPED_CHILD(Extensions,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_CHILD(Status,SAMLConstants::SAML20P_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
    
            void processAttribute(const DOMAttr* attribute) {
                PROC_ID_ATTRIB(ID,ID,NULL);
                PROC_STRING_ATTRIB(Version,VER,NULL);
                PROC_STRING_ATTRIB(InResponseTo,INRESPONSETO,NULL);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,NULL);
                PROC_STRING_ATTRIB(Destination,DESTINATION,NULL);
                PROC_STRING_ATTRIB(Consent,CONSENT,NULL);
                AbstractXMLObjectUnmarshaller::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL ResponseImpl : public virtual Response, public StatusResponseImpl
        {
        public:
            virtual ~ResponseImpl() { }
    
            ResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) { }
                
            ResponseImpl(const ResponseImpl& src) : AbstractXMLObject(src), StatusResponseImpl(src) {
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        Assertion* assertion=dynamic_cast<Assertion*>(*i);
                        if (assertion) {
                            getAssertions().push_back(assertion->cloneAssertion());
                            continue;
                        }
                        EncryptedAssertion* encAssertion=dynamic_cast<EncryptedAssertion*>(*i);
                        if (encAssertion) {
                            getEncryptedAssertions().push_back(encAssertion->cloneEncryptedAssertion());
                            continue;
                        }
                    }
                }

            }
            
            IMPL_XMLOBJECT_CLONE(Response);
            IMPL_TYPED_FOREIGN_CHILDREN(Assertion,saml2,m_children.end());
            IMPL_TYPED_FOREIGN_CHILDREN(EncryptedAssertion,saml2,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILDREN(Assertion,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(EncryptedAssertion,saml2,SAMLConstants::SAML20_NS,false);
                StatusResponseImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL ArtifactResolveImpl : public virtual ArtifactResolve, public RequestImpl
        {
            void init() {
                m_Artifact=NULL;
                m_children.push_back(NULL);
                m_pos_Artifact=m_pos_Extensions;
                ++m_pos_Artifact;
            }
        public:
            virtual ~ArtifactResolveImpl() { }
    
            ArtifactResolveImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            { 
                init();
            }
                
            ArtifactResolveImpl(const ArtifactResolveImpl& src) : AbstractXMLObject(src), RequestImpl(src) {
                init();
                if(src.getArtifact())
                    setArtifact(src.getArtifact()->cloneArtifact());
            }
            
            IMPL_XMLOBJECT_CLONE(ArtifactResolve);
            IMPL_TYPED_CHILD(Artifact);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Artifact,SAMLConstants::SAML20P_NS,false);
                RequestImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL ArtifactResponseImpl : public virtual ArtifactResponse, public StatusResponseImpl
        {
            void init() {
                m_Payload=NULL;
                m_children.push_back(NULL);
                m_pos_Payload=m_pos_Status;
                ++m_pos_Payload;
            }
        public:
            virtual ~ArtifactResponseImpl() { }
    
            ArtifactResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            ArtifactResponseImpl(const ArtifactResponseImpl& src) : AbstractXMLObject(src), StatusResponseImpl(src) {
                init();
                if (src.getPayload())
                    setPayload(getPayload()->clone());

            }
            
            IMPL_XMLOBJECT_CLONE(ArtifactResponse);
            IMPL_XMLOBJECT_CHILD(Payload);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                // These are valid elements for the parent StatusResponse, so don't process these.
                // If not one of these, then it must be the payload.
                if (
                    ! XMLHelper::isNodeNamed(root,SAMLConstants::SAML20_NS,saml2::Issuer::LOCAL_NAME) &&
                    ! XMLHelper::isNodeNamed(root,XMLConstants::XMLSIG_NS,xmlsignature::Signature::LOCAL_NAME) &&
                    ! XMLHelper::isNodeNamed(root,SAMLConstants::SAML20P_NS,saml2p::Extensions::LOCAL_NAME) &&
                    ! XMLHelper::isNodeNamed(root,SAMLConstants::SAML20P_NS,saml2p::Status::LOCAL_NAME)
                   )
                {
                    setPayload(childXMLObject);
                    return;
                }

                StatusResponseImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL NewEncryptedIDImpl : public virtual NewEncryptedID,
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
            NewEncryptedIDImpl()
            {
                init();
            }
            
        public:
            virtual ~NewEncryptedIDImpl() {}
    
            NewEncryptedIDImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            NewEncryptedIDImpl(const NewEncryptedIDImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                init();
                if (src.getEncryptedData())
                    setEncryptedData(src.getEncryptedData()->cloneEncryptedData());
                VectorOf(xmlencryption::EncryptedKey) v=getEncryptedKeys();
                for (vector<xmlencryption::EncryptedKey*>::const_iterator i=src.m_EncryptedKeys.begin(); i!=src.m_EncryptedKeys.end(); i++) {
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
        
            IMPL_XMLOBJECT_CLONE(NewEncryptedID);
            EncryptedElementType* cloneEncryptedElementType() const {
                return new NewEncryptedIDImpl(*this);
            }

            IMPL_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption);
            IMPL_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption,m_children.end());
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption,XMLConstants::XMLENC_NS,false);
                PROC_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption,XMLConstants::XMLENC_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL TerminateImpl : public virtual Terminate,
            public AbstractChildlessElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            public:
                virtual ~TerminateImpl() { }

                TerminateImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) { }

                TerminateImpl(const TerminateImpl& src) : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src) {
                }

                IMPL_XMLOBJECT_CLONE(Terminate);

            protected:
                // has no attributes or children
        };

        class SAML_DLLLOCAL ManageNameIDRequestImpl : public virtual ManageNameIDRequest, public RequestImpl
        {
            void init() {
                m_NameID=NULL;
                m_EncryptedID=NULL;
                m_NewID=NULL;
                m_NewEncryptedID=NULL;
                m_Terminate=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
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
            virtual ~ManageNameIDRequestImpl() { }
    
            ManageNameIDRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            ManageNameIDRequestImpl(const ManageNameIDRequestImpl& src) : AbstractXMLObject(src), RequestImpl(src) {
                init();

                if (src.getNameID())
                    setNameID(src.getNameID()->cloneNameID());
                if (src.getEncryptedID())
                    setEncryptedID(src.getEncryptedID()->cloneEncryptedID());
                if (src.getNewID())
                    setNewID(src.getNewID()->cloneNewID());
                if (src.getNewEncryptedID())
                    setNewEncryptedID(src.getNewEncryptedID()->cloneNewEncryptedID());
                if (src.getTerminate())
                    setTerminate(src.getTerminate()->cloneTerminate());

            }
            
            IMPL_XMLOBJECT_CLONE(ManageNameIDRequest);

            IMPL_TYPED_FOREIGN_CHILD(NameID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            IMPL_TYPED_CHILD(NewID);
            IMPL_TYPED_CHILD(NewEncryptedID);
            IMPL_TYPED_CHILD(Terminate);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(NameID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(EncryptedID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(NewID,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_CHILD(NewEncryptedID,SAMLConstants::SAML20P_NS,false);
                PROC_TYPED_CHILD(Terminate,SAMLConstants::SAML20P_NS,false);
                RequestImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL ManageNameIDResponseImpl : public virtual ManageNameIDResponse, public StatusResponseImpl
        {
            public:
                virtual ~ManageNameIDResponseImpl() { }
    
                ManageNameIDResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) { }
                
                ManageNameIDResponseImpl(const ManageNameIDResponseImpl& src) : AbstractXMLObject(src), StatusResponseImpl(src) {
                }

                IMPL_XMLOBJECT_CLONE(ManageNameIDResponse);
        };

        class SAML_DLLLOCAL LogoutRequestImpl : public virtual LogoutRequest, public RequestImpl
        {
            void init() {
                m_Reason=NULL;
                m_NotOnOrAfter=NULL;

                m_BaseID=NULL;
                m_NameID=NULL;
                m_EncryptedID=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
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
    
            LogoutRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            LogoutRequestImpl(const LogoutRequestImpl& src) : AbstractXMLObject(src), RequestImpl(src) {
                init();

                setReason(src.getReason());
                setNotOnOrAfter(src.getNotOnOrAfter());

                if (src.getBaseID())
                    setBaseID(src.getBaseID()->cloneBaseID());
                if (src.getNameID())
                    setNameID(src.getNameID()->cloneNameID());
                if (src.getEncryptedID())
                    setEncryptedID(src.getEncryptedID()->cloneEncryptedID());

                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        SessionIndex* si = dynamic_cast<SessionIndex*>(*i);
                        if (si) {
                            getSessionIndexs().push_back(si->cloneSessionIndex());
                            continue;
                        }
                    }
                }
            }
            
            IMPL_XMLOBJECT_CLONE(LogoutRequest);

            IMPL_STRING_ATTRIB(Reason);
            IMPL_DATETIME_ATTRIB(NotOnOrAfter,LLONG_MAX);
            IMPL_TYPED_FOREIGN_CHILD(BaseID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(NameID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            IMPL_TYPED_CHILDREN(SessionIndex,m_children.end());
    
        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Reason,REASON,NULL);
                MARSHALL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,NULL);
                RequestImpl::marshallAttributes(domElement);
            }
    
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(BaseID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(NameID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(EncryptedID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILDREN(SessionIndex,SAMLConstants::SAML20P_NS,false);
                RequestImpl::processChildElement(childXMLObject,root);
            }
            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Reason,REASON,NULL);
                PROC_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,NULL);
                RequestImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL LogoutResponseImpl : public virtual LogoutResponse, public StatusResponseImpl
        {
            public:
                virtual ~LogoutResponseImpl() { }
    
                LogoutResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) { }
                
                LogoutResponseImpl(const LogoutResponseImpl& src) : AbstractXMLObject(src), StatusResponseImpl(src) {
                }

                IMPL_XMLOBJECT_CLONE(LogoutResponse);
        };


        class SAML_DLLLOCAL NameIDMappingRequestImpl : public virtual NameIDMappingRequest, public RequestImpl
        {
            void init() {
                m_BaseID=NULL;
                m_NameID=NULL;
                m_EncryptedID=NULL;
                m_NameIDPolicy=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_children.push_back(NULL);
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
            virtual ~NameIDMappingRequestImpl() { }
    
            NameIDMappingRequestImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            NameIDMappingRequestImpl(const NameIDMappingRequestImpl& src) : AbstractXMLObject(src), RequestImpl(src) {
                init();

                if (src.getBaseID())
                    setBaseID(src.getBaseID()->cloneBaseID());
                if (src.getNameID())
                    setNameID(src.getNameID()->cloneNameID());
                if (src.getEncryptedID())
                    setEncryptedID(src.getEncryptedID()->cloneEncryptedID());
                if (src.getNameIDPolicy())
                    setNameIDPolicy(src.getNameIDPolicy()->cloneNameIDPolicy());

            }
            
            IMPL_XMLOBJECT_CLONE(NameIDMappingRequest);

            IMPL_TYPED_FOREIGN_CHILD(BaseID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(NameID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
            IMPL_TYPED_CHILD(NameIDPolicy);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(BaseID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(NameID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(EncryptedID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_CHILD(NameIDPolicy,SAMLConstants::SAML20P_NS,false);
                RequestImpl::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL NameIDMappingResponseImpl : public virtual NameIDMappingResponse, public StatusResponseImpl
        {
            void init() {
                m_NameID=NULL;
                m_EncryptedID=NULL;
                m_children.push_back(NULL);
                m_children.push_back(NULL);
                m_pos_NameID=m_pos_Status;
                ++m_pos_NameID;
                m_pos_EncryptedID=m_pos_NameID;
                ++m_pos_EncryptedID;
            }
        public:
            virtual ~NameIDMappingResponseImpl() { }
    
            NameIDMappingResponseImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType)
            {
                init();
            }
                
            NameIDMappingResponseImpl(const NameIDMappingResponseImpl& src) : AbstractXMLObject(src), StatusResponseImpl(src) {
                init();

                if (src.getNameID())
                    setNameID(getNameID()->cloneNameID());
                if (src.getEncryptedID())
                    setEncryptedID(getEncryptedID()->cloneEncryptedID());

            }
            
            IMPL_XMLOBJECT_CLONE(NameIDMappingResponse);
            IMPL_TYPED_FOREIGN_CHILD(NameID,saml2);
            IMPL_TYPED_FOREIGN_CHILD(EncryptedID,saml2);
    
        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_FOREIGN_CHILD(NameID,saml2,SAMLConstants::SAML20_NS,false);
                PROC_TYPED_FOREIGN_CHILD(EncryptedID,saml2,SAMLConstants::SAML20_NS,false);
                StatusResponseImpl::processChildElement(childXMLObject,root);
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
IMPL_XMLOBJECTBUILDER(StatusResponse);
IMPL_XMLOBJECTBUILDER(Terminate);


// Unicode literals
const XMLCh Artifact::LOCAL_NAME[] = UNICODE_LITERAL_8(A,r,t,i,f,a,c,t);
const XMLCh ArtifactResolve::LOCAL_NAME[] = UNICODE_LITERAL_15(A,r,t,i,f,a,c,t,R,e,s,o,l,v,e);
const XMLCh ArtifactResolve::TYPE_NAME[] = UNICODE_LITERAL_19(A,r,t,i,f,a,c,t,R,e,s,o,l,v,e,T,y,p,e);
const XMLCh ArtifactResponse::LOCAL_NAME[] = UNICODE_LITERAL_16(A,r,t,i,f,a,c,t,R,e,s,p,o,n,s,e);
const XMLCh ArtifactResponse::TYPE_NAME[] = UNICODE_LITERAL_20(A,r,t,i,f,a,c,t,R,e,s,p,o,n,s,e,T,y,p,e);
const XMLCh AssertionIDRequest::LOCAL_NAME[] = UNICODE_LITERAL_18(A,s,s,e,r,t,i,o,n,I,D,R,e,q,u,e,s,t);
const XMLCh AssertionIDRequest::TYPE_NAME[] = UNICODE_LITERAL_22(A,s,s,e,r,t,i,o,n,I,D,R,e,q,u,e,s,t,T,y,p,e);
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
const XMLCh Request::LOCAL_NAME[] = {chNull};
const XMLCh Request::TYPE_NAME[] = UNICODE_LITERAL_19(R,e,q,u,e,s,t,A,b,s,t,r,a,c,t,T,y,p,e);
const XMLCh Request::ID_ATTRIB_NAME[] = UNICODE_LITERAL_2(I,D);
const XMLCh Request::VER_ATTRIB_NAME[] = UNICODE_LITERAL_7(V,e,r,s,i,o,n);
const XMLCh Request::ISSUEINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_12(I,s,s,u,e,I,n,s,t,a,n,t);
const XMLCh Request::DESTINATION_ATTRIB_NAME[] = UNICODE_LITERAL_11(D,e,s,t,i,n,a,t,i,o,n);
const XMLCh Request::CONSENT_ATTRIB_NAME[] = UNICODE_LITERAL_7(C,o,n,s,e,n,t);
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
const XMLCh StatusResponse::LOCAL_NAME[] = {chNull};
const XMLCh StatusResponse::TYPE_NAME[] = UNICODE_LITERAL_18(S,t,a,t,u,s,R,e,s,p,o,n,s,e,T,y,p,e);
const XMLCh StatusResponse::ID_ATTRIB_NAME[] = UNICODE_LITERAL_2(I,D);
const XMLCh StatusResponse::INRESPONSETO_ATTRIB_NAME[] = UNICODE_LITERAL_12(I,n,R,e,s,p,o,n,s,e,T,o);
const XMLCh StatusResponse::VER_ATTRIB_NAME[] = UNICODE_LITERAL_7(V,e,r,s,i,o,n);
const XMLCh StatusResponse::ISSUEINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_12(I,s,s,u,e,I,n,s,t,a,n,t);
const XMLCh StatusResponse::DESTINATION_ATTRIB_NAME[] = UNICODE_LITERAL_11(D,e,s,t,i,n,a,t,i,o,n);
const XMLCh StatusResponse::CONSENT_ATTRIB_NAME[] = UNICODE_LITERAL_7(C,o,n,s,e,n,t);
const XMLCh SubjectQuery::LOCAL_NAME[] = {chNull};
const XMLCh SubjectQuery::TYPE_NAME[] = UNICODE_LITERAL_16(S,u,b,j,e,c,t,Q,u,e,r,y,T,y,p,e);
const XMLCh Terminate::LOCAL_NAME[] = UNICODE_LITERAL_9(T,e,r,m,i,n,a,t,e);
const XMLCh Terminate::TYPE_NAME[] = UNICODE_LITERAL_13(T,e,r,m,i,n,a,t,e,T,y,p,e);
