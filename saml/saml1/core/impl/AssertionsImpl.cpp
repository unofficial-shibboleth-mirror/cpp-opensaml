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
 * AssertionsImpl.cpp
 *
 * Implementation classes for SAML 1.x Assertions schema.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/core/Assertions.h"
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
#include <limits.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml::saml1;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;
using xmlconstants::XMLSIG_NS;
using xmlconstants::XML_ONE;
using samlconstants::SAML1_NS;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {
    namespace saml1 {

        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AssertionIDReference);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,Audience);
        DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,ConfirmationMethod);

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

        class SAML_DLLLOCAL AudienceRestrictionConditionImpl : public virtual AudienceRestrictionCondition,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AudienceRestrictionConditionImpl() {}

            AudienceRestrictionConditionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            AudienceRestrictionConditionImpl(const AudienceRestrictionConditionImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                VectorOf(Audience) v=getAudiences();
                for (vector<Audience*>::const_iterator i=src.m_Audiences.begin(); i!=src.m_Audiences.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAudience());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(AudienceRestrictionCondition);
            Condition* cloneCondition() const {
                return cloneAudienceRestrictionCondition();
            }
            IMPL_TYPED_CHILDREN(Audience,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(Audience,SAML1_NS,false);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL DoNotCacheConditionImpl : public virtual DoNotCacheCondition,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~DoNotCacheConditionImpl() {}

            DoNotCacheConditionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            DoNotCacheConditionImpl(const DoNotCacheConditionImpl& src)
                : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
            }

            IMPL_XMLOBJECT_CLONE(DoNotCacheCondition);
            Condition* cloneCondition() const {
                return cloneDoNotCacheCondition();
            }
        };

        class SAML_DLLLOCAL ConditionsImpl : public virtual Conditions,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
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
                        AudienceRestrictionCondition* arc=dynamic_cast<AudienceRestrictionCondition*>(*i);
                        if (arc) {
                            getAudienceRestrictionConditions().push_back(arc->cloneAudienceRestrictionCondition());
                            continue;
                        }

                        DoNotCacheCondition* dncc=dynamic_cast<DoNotCacheCondition*>(*i);
                        if (dncc) {
                            getDoNotCacheConditions().push_back(dncc->cloneDoNotCacheCondition());
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

            void init() {
                m_NotBefore=m_NotOnOrAfter=nullptr;
            }

            IMPL_XMLOBJECT_CLONE(Conditions);
            IMPL_DATETIME_ATTRIB(NotBefore,0);
            IMPL_DATETIME_ATTRIB(NotOnOrAfter,SAMLTIME_MAX);
            IMPL_TYPED_CHILDREN(AudienceRestrictionCondition, m_children.end());
            IMPL_TYPED_CHILDREN(DoNotCacheCondition,m_children.end());
            IMPL_TYPED_CHILDREN(Condition,m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_DATETIME_ATTRIB(NotBefore,NOTBEFORE,nullptr);
                MARSHALL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AudienceRestrictionCondition,SAML1_NS,true);
                PROC_TYPED_CHILDREN(DoNotCacheCondition,SAML1_NS,true);
                PROC_TYPED_CHILDREN(Condition,SAML1_NS,true);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_DATETIME_ATTRIB(NotBefore,NOTBEFORE,nullptr);
                PROC_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER,nullptr);
            }
        };

        class SAML_DLLLOCAL NameIdentifierImpl : public virtual NameIdentifier,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~NameIdentifierImpl() {
                XMLString::release(&m_Format);
                XMLString::release(&m_NameQualifier);
            }

            NameIdentifierImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                    : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            NameIdentifierImpl(const NameIdentifierImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setFormat(src.getFormat());
                setNameQualifier(src.getNameQualifier());
            }

            void init() {
                m_Format=m_NameQualifier=nullptr;
            }

            IMPL_XMLOBJECT_CLONE(NameIdentifier);
            IMPL_STRING_ATTRIB(Format);
            IMPL_STRING_ATTRIB(NameQualifier);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Format,FORMAT,nullptr);
                MARSHALL_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Format,FORMAT,nullptr);
                PROC_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER,nullptr);
            }
        };

        class SAML_DLLLOCAL SubjectConfirmationDataImpl : public virtual SubjectConfirmationData, public AnyElementImpl
        {
        public:
            virtual ~SubjectConfirmationDataImpl() {}

            SubjectConfirmationDataImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            SubjectConfirmationDataImpl(const SubjectConfirmationDataImpl& src) : AbstractXMLObject(src), AnyElementImpl(src) {
            }

            IMPL_XMLOBJECT_CLONE(SubjectConfirmationData);
        };

        class SAML_DLLLOCAL SubjectConfirmationImpl : public virtual SubjectConfirmation,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~SubjectConfirmationImpl() {}

            SubjectConfirmationImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SubjectConfirmationImpl(const SubjectConfirmationImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                if (src.getSubjectConfirmationData())
                    setSubjectConfirmationData(src.getSubjectConfirmationData()->clone());
                if (src.getKeyInfo())
                    setKeyInfo(src.getKeyInfo()->cloneKeyInfo());
                VectorOf(ConfirmationMethod) v=getConfirmationMethods();
                for (vector<ConfirmationMethod*>::const_iterator i=src.m_ConfirmationMethods.begin(); i!=src.m_ConfirmationMethods.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneConfirmationMethod());
                    }
                }
            }

            void init() {
                m_SubjectConfirmationData=nullptr;
                m_KeyInfo=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_SubjectConfirmationData=m_children.begin();
                m_pos_KeyInfo=m_pos_SubjectConfirmationData;
                ++m_pos_KeyInfo;
            }

            IMPL_XMLOBJECT_CLONE(SubjectConfirmation);
            IMPL_TYPED_CHILDREN(ConfirmationMethod,m_pos_SubjectConfirmationData);
            IMPL_XMLOBJECT_CHILD(SubjectConfirmationData);
            IMPL_TYPED_CHILD(KeyInfo);

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(ConfirmationMethod,SAML1_NS,false);
                PROC_TYPED_CHILD(KeyInfo,XMLSIG_NS,false);

                // Anything else we'll assume is the data.
                if (getSubjectConfirmationData())
                    throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
                setSubjectConfirmationData(childXMLObject);
            }
        };

        class SAML_DLLLOCAL SubjectImpl : public virtual Subject,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~SubjectImpl() {}

            SubjectImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SubjectImpl(const SubjectImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                if (src.getNameIdentifier())
                    setNameIdentifier(src.getNameIdentifier()->cloneNameIdentifier());
                if (src.getSubjectConfirmation())
                    setSubjectConfirmation(src.getSubjectConfirmation()->cloneSubjectConfirmation());
            }

            void init() {
                m_NameIdentifier=nullptr;
                m_SubjectConfirmation=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_pos_NameIdentifier=m_children.begin();
                m_pos_SubjectConfirmation=m_pos_NameIdentifier;
                ++m_pos_SubjectConfirmation;
            }

            IMPL_XMLOBJECT_CLONE(Subject);
            IMPL_TYPED_CHILD(NameIdentifier);
            IMPL_TYPED_CHILD(SubjectConfirmation);

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(NameIdentifier,SAML1_NS,true);
                PROC_TYPED_CHILD(SubjectConfirmation,SAML1_NS,true);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
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

        class SAML_DLLLOCAL SubjectStatementImpl : public virtual SubjectStatement,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_Subject=nullptr;
                m_children.push_back(nullptr);
                m_pos_Subject=m_children.begin();
            }
        protected:
            SubjectStatementImpl() {
                init();
            }
        public:
            virtual ~SubjectStatementImpl() {}

            SubjectStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SubjectStatementImpl(const SubjectStatementImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                if (src.getSubject())
                    setSubject(src.getSubject()->cloneSubject());
            }

            IMPL_TYPED_CHILD(Subject);

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Subject,SAML1_NS,true);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL SubjectLocalityImpl : public virtual SubjectLocality,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~SubjectLocalityImpl() {
                XMLString::release(&m_IPAddress);
                XMLString::release(&m_DNSAddress);
            }

            SubjectLocalityImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            SubjectLocalityImpl(const SubjectLocalityImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setIPAddress(src.getIPAddress());
                setDNSAddress(src.getDNSAddress());
            }

            void init() {
                m_IPAddress=m_DNSAddress=nullptr;
            }

            IMPL_XMLOBJECT_CLONE(SubjectLocality);
            IMPL_STRING_ATTRIB(IPAddress);
            IMPL_STRING_ATTRIB(DNSAddress);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(IPAddress,IPADDRESS,nullptr);
                MARSHALL_STRING_ATTRIB(DNSAddress,DNSADDRESS,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(IPAddress,IPADDRESS,nullptr);
                PROC_STRING_ATTRIB(DNSAddress,DNSADDRESS,nullptr);
            }
        };

        class SAML_DLLLOCAL AuthorityBindingImpl : public virtual AuthorityBinding,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AuthorityBindingImpl() {
                delete m_AuthorityKind;
                XMLString::release(&m_Location);
                XMLString::release(&m_Binding);
            }

            AuthorityBindingImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AuthorityBindingImpl(const AuthorityBindingImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setAuthorityKind(src.getAuthorityKind());
                setLocation(src.getLocation());
                setBinding(src.getBinding());
            }

            void init() {
                m_AuthorityKind=nullptr;
                m_Location=m_Binding=nullptr;
            }

            IMPL_XMLOBJECT_CLONE(AuthorityBinding);
            IMPL_XMLOBJECT_ATTRIB(AuthorityKind,xmltooling::QName);
            IMPL_STRING_ATTRIB(Location);
            IMPL_STRING_ATTRIB(Binding);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_QNAME_ATTRIB(AuthorityKind,AUTHORITYKIND,nullptr);
                MARSHALL_STRING_ATTRIB(Location,LOCATION,nullptr);
                MARSHALL_STRING_ATTRIB(Binding,BINDING,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_QNAME_ATTRIB(AuthorityKind,AUTHORITYKIND,nullptr);
                PROC_STRING_ATTRIB(Location,LOCATION,nullptr);
                PROC_STRING_ATTRIB(Binding,BINDING,nullptr);
            }
        };

        class SAML_DLLLOCAL AuthenticationStatementImpl : public virtual AuthenticationStatement, public SubjectStatementImpl
        {
        public:
            virtual ~AuthenticationStatementImpl() {
                XMLString::release(&m_AuthenticationMethod);
                delete m_AuthenticationInstant;
            }

            AuthenticationStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AuthenticationStatementImpl(const AuthenticationStatementImpl& src) : AbstractXMLObject(src), SubjectStatementImpl(src) {
                init();
                setAuthenticationMethod(src.getAuthenticationMethod());
                setAuthenticationInstant(src.getAuthenticationInstant());
                if (src.getSubjectLocality())
                    setSubjectLocality(src.getSubjectLocality()->cloneSubjectLocality());
                VectorOf(AuthorityBinding) v=getAuthorityBindings();
                for (vector<AuthorityBinding*>::const_iterator i=src.m_AuthorityBindings.begin(); i!=src.m_AuthorityBindings.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAuthorityBinding());
                    }
                }
            }

            void init() {
                m_AuthenticationMethod=nullptr;
                m_AuthenticationInstant=nullptr;
                m_SubjectLocality=nullptr;
                m_children.push_back(nullptr);
                m_pos_SubjectLocality=m_pos_Subject;
                ++m_pos_SubjectLocality;
            }

            IMPL_XMLOBJECT_CLONE(AuthenticationStatement);
            SubjectStatement* cloneSubjectStatement() const {
                return cloneAuthenticationStatement();
            }
            Statement* cloneStatement() const {
                return cloneAuthenticationStatement();
            }
            IMPL_STRING_ATTRIB(AuthenticationMethod);
            IMPL_DATETIME_ATTRIB(AuthenticationInstant,0);
            IMPL_TYPED_CHILD(SubjectLocality);
            IMPL_TYPED_CHILDREN(AuthorityBinding, m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(AuthenticationMethod,AUTHENTICATIONMETHOD,nullptr);
                MARSHALL_DATETIME_ATTRIB(AuthenticationInstant,AUTHENTICATIONINSTANT,nullptr);
                SubjectStatementImpl::marshallAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(SubjectLocality,SAML1_NS,false);
                PROC_TYPED_CHILDREN(AuthorityBinding,SAML1_NS,false);
                SubjectStatementImpl::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(AuthenticationMethod,AUTHENTICATIONMETHOD,nullptr);
                PROC_DATETIME_ATTRIB(AuthenticationInstant,AUTHENTICATIONINSTANT,nullptr);
                SubjectStatementImpl::processAttribute(attribute);
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

            ActionImpl(const ActionImpl& src) : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
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
                        AssertionIDReference* ref=dynamic_cast<AssertionIDReference*>(*i);
                        if (ref) {
                            getAssertionIDReferences().push_back(ref->cloneAssertionIDReference());
                            continue;
                        }

                        Assertion* assertion=dynamic_cast<Assertion*>(*i);
                        if (assertion) {
                            getAssertions().push_back(assertion->cloneAssertion());
                            continue;
                        }
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(Evidence);
            IMPL_TYPED_CHILDREN(AssertionIDReference,m_children.end());
            IMPL_TYPED_CHILDREN(Assertion,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AssertionIDReference,SAML1_NS,false);
                PROC_TYPED_CHILDREN(Assertion,SAML1_NS,true);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AuthorizationDecisionStatementImpl
            : public virtual AuthorizationDecisionStatement, public SubjectStatementImpl
        {
        public:
            virtual ~AuthorizationDecisionStatementImpl() {
                XMLString::release(&m_Resource);
                XMLString::release(&m_Decision);
            }

            AuthorizationDecisionStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AuthorizationDecisionStatementImpl(const AuthorizationDecisionStatementImpl& src)
                    : AbstractXMLObject(src), SubjectStatementImpl(src) {
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

            void init() {
                m_Resource=nullptr;
                m_Decision=nullptr;
                m_Evidence=nullptr;
                m_children.push_back(nullptr);
                m_pos_Evidence=m_pos_Subject;
                ++m_pos_Evidence;
            }

            IMPL_XMLOBJECT_CLONE(AuthorizationDecisionStatement);
            SubjectStatement* cloneSubjectStatement() const {
                return cloneAuthorizationDecisionStatement();
            }
            Statement* cloneStatement() const {
                return cloneAuthorizationDecisionStatement();
            }
            IMPL_STRING_ATTRIB(Resource);
            IMPL_STRING_ATTRIB(Decision);
            IMPL_TYPED_CHILD(Evidence);
            IMPL_TYPED_CHILDREN(Action, m_pos_Evidence);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(Resource,RESOURCE,nullptr);
                MARSHALL_STRING_ATTRIB(Decision,DECISION,nullptr);
                SubjectStatementImpl::marshallAttributes(domElement);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Evidence,SAML1_NS,false);
                PROC_TYPED_CHILDREN(Action,SAML1_NS,false);
                SubjectStatementImpl::processChildElement(childXMLObject,root);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(Resource,RESOURCE,nullptr);
                PROC_STRING_ATTRIB(Decision,DECISION,nullptr);
                SubjectStatementImpl::processAttribute(attribute);
            }
        };

        class SAML_DLLLOCAL AttributeDesignatorImpl : public virtual AttributeDesignator,
            public AbstractSimpleElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AttributeDesignatorImpl() {
                XMLString::release(&m_AttributeName);
                XMLString::release(&m_AttributeNamespace);
            }

            AttributeDesignatorImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AttributeDesignatorImpl(const AttributeDesignatorImpl& src)
                    : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setAttributeName(src.getAttributeName());
                setAttributeNamespace(src.getAttributeNamespace());
            }

            void init() {
                m_AttributeName=m_AttributeNamespace=nullptr;
            }

            IMPL_XMLOBJECT_CLONE(AttributeDesignator);
            IMPL_STRING_ATTRIB(AttributeName);
            IMPL_STRING_ATTRIB(AttributeNamespace);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(AttributeName,ATTRIBUTENAME,nullptr);
                MARSHALL_STRING_ATTRIB(AttributeNamespace,ATTRIBUTENAMESPACE,nullptr);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(AttributeName,ATTRIBUTENAME,nullptr);
                PROC_STRING_ATTRIB(AttributeNamespace,ATTRIBUTENAMESPACE,nullptr);
            }
        };

        class SAML_DLLLOCAL AttributeImpl : public virtual Attribute,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
        public:
            virtual ~AttributeImpl() {
                XMLString::release(&m_AttributeName);
                XMLString::release(&m_AttributeNamespace);
            }

            AttributeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AttributeImpl(const AttributeImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setAttributeName(src.getAttributeName());
                setAttributeNamespace(src.getAttributeNamespace());
                VectorOf(XMLObject) v=getAttributeValues();
                for (vector<XMLObject*>::const_iterator i=src.m_AttributeValues.begin(); i!=src.m_AttributeValues.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->clone());
                    }
                }
            }

            void init() {
                m_AttributeName=m_AttributeNamespace=nullptr;
            }

            IMPL_XMLOBJECT_CLONE(Attribute);
            AttributeDesignator* cloneAttributeDesignator() const {
                return cloneAttribute();
            }
            IMPL_STRING_ATTRIB(AttributeName);
            IMPL_STRING_ATTRIB(AttributeNamespace);
            IMPL_XMLOBJECT_CHILDREN(AttributeValue,m_children.end());

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                MARSHALL_STRING_ATTRIB(AttributeName,ATTRIBUTENAME,nullptr);
                MARSHALL_STRING_ATTRIB(AttributeNamespace,ATTRIBUTENAMESPACE,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                getAttributeValues().push_back(childXMLObject);
            }

            void processAttribute(const DOMAttr* attribute) {
                PROC_STRING_ATTRIB(AttributeName,ATTRIBUTENAME,nullptr);
                PROC_STRING_ATTRIB(AttributeNamespace,ATTRIBUTENAMESPACE,nullptr);
            }
        };

        class SAML_DLLLOCAL AttributeValueImpl : public virtual AttributeValue, public AnyElementImpl
        {
        public:
            virtual ~AttributeValueImpl() {}

            AttributeValueImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            AttributeValueImpl(const AttributeValueImpl& src) : AbstractXMLObject(src), AnyElementImpl(src) {}

            IMPL_XMLOBJECT_CLONE(AttributeValue);
        };

        class SAML_DLLLOCAL AttributeStatementImpl : public virtual AttributeStatement, public SubjectStatementImpl
        {
        public:
            virtual ~AttributeStatementImpl() {}

            AttributeStatementImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            }

            AttributeStatementImpl(const AttributeStatementImpl& src)
                    : AbstractXMLObject(src), SubjectStatementImpl(src) {
                VectorOf(Attribute) v=getAttributes();
                for (vector<Attribute*>::const_iterator i=src.m_Attributes.begin(); i!=src.m_Attributes.end(); i++) {
                    if (*i) {
                        v.push_back((*i)->cloneAttribute());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(AttributeStatement);
            SubjectStatement* cloneSubjectStatement() const {
                return cloneAttributeStatement();
            }
            Statement* cloneStatement() const {
                return cloneAttributeStatement();
            }
            IMPL_TYPED_CHILDREN(Attribute, m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(Attribute,SAML1_NS,true);
                SubjectStatementImpl::processChildElement(childXMLObject,root);
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
                        AssertionIDReference* ref=dynamic_cast<AssertionIDReference*>(*i);
                        if (ref) {
                            getAssertionIDReferences().push_back(ref->cloneAssertionIDReference());
                            continue;
                        }

                        Assertion* assertion=dynamic_cast<Assertion*>(*i);
                        if (assertion) {
                            getAssertions().push_back(assertion->cloneAssertion());
                            continue;
                        }

                        getUnknownXMLObjects().push_back((*i)->clone());
                    }
                }
            }

            IMPL_XMLOBJECT_CLONE(Advice);
            IMPL_TYPED_CHILDREN(AssertionIDReference,m_children.end());
            IMPL_TYPED_CHILDREN(Assertion,m_children.end());
            IMPL_XMLOBJECT_CHILDREN(UnknownXMLObject,m_children.end());

        protected:
            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILDREN(AssertionIDReference,SAML1_NS,false);
                PROC_TYPED_CHILDREN(Assertion,SAML1_NS,true);

                // Unknown child.
                const XMLCh* nsURI=root->getNamespaceURI();
                if (!XMLString::equals(nsURI,SAML1_NS) && nsURI && *nsURI) {
                    getUnknownXMLObjects().push_back(childXMLObject);
                    return;
                }

                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }
        };

        class SAML_DLLLOCAL AssertionImpl : public virtual Assertion,
            public AbstractComplexElement,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
        {
            void init() {
                m_MinorVersion=nullptr;
                m_AssertionID=nullptr;
                m_Issuer=nullptr;
                m_IssueInstant=nullptr;
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_children.push_back(nullptr);
                m_Conditions=nullptr;
                m_Advice=nullptr;
                m_Signature=nullptr;
                m_pos_Conditions=m_children.begin();
                m_pos_Advice=m_pos_Conditions;
                ++m_pos_Advice;
                m_pos_Signature=m_pos_Advice;
                ++m_pos_Signature;
            }
        public:
            virtual ~AssertionImpl() {
                XMLString::release(&m_MinorVersion);
                XMLString::release(&m_AssertionID);
                XMLString::release(&m_Issuer);
                delete m_IssueInstant;
            }

            AssertionImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
                init();
            }

            AssertionImpl(const AssertionImpl& src)
                    : AbstractXMLObject(src), AbstractComplexElement(src), AbstractDOMCachingXMLObject(src) {
                init();
                setMinorVersion(src.m_MinorVersion);
                setAssertionID(src.getAssertionID());
                setIssuer(src.getIssuer());
                setIssueInstant(src.getIssueInstant());
                if (src.getConditions())
                    setConditions(src.getConditions()->cloneConditions());
                if (src.getAdvice())
                    setAdvice(src.getAdvice()->cloneAdvice());
                if (src.getSignature())
                    setSignature(src.getSignature()->cloneSignature());
                for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                    if (*i) {
                        AuthenticationStatement* authst=dynamic_cast<AuthenticationStatement*>(*i);
                        if (authst) {
                            getAuthenticationStatements().push_back(authst->cloneAuthenticationStatement());
                            continue;
                        }

                        AttributeStatement* attst=dynamic_cast<AttributeStatement*>(*i);
                        if (attst) {
                            getAttributeStatements().push_back(attst->cloneAttributeStatement());
                            continue;
                        }

                        AuthorizationDecisionStatement* authzst=dynamic_cast<AuthorizationDecisionStatement*>(*i);
                        if (authzst) {
                            getAuthorizationDecisionStatements().push_back(authzst->cloneAuthorizationDecisionStatement());
                            continue;
                        }

                        SubjectStatement* subst=dynamic_cast<SubjectStatement*>(*i);
                        if (subst) {
                            getSubjectStatements().push_back(subst->cloneSubjectStatement());
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
            IMPL_INTEGER_ATTRIB(MinorVersion);
            IMPL_STRING_ATTRIB(AssertionID);    // have to special-case getXMLID
            const XMLCh* getXMLID() const {
                pair<bool,int> v = getMinorVersion();
                return (!v.first || v.second > 0) ? m_AssertionID : nullptr;
            }
            const XMLCh* getID() const {
                return getAssertionID();
            }
            void releaseDOM() const {
                if (getDOM())
                    getDOM()->removeAttributeNS(nullptr, ASSERTIONID_ATTRIB_NAME);
                AbstractDOMCachingXMLObject::releaseDOM();
            }
            IMPL_STRING_ATTRIB(Issuer);
            IMPL_DATETIME_ATTRIB(IssueInstant,0);
            IMPL_TYPED_CHILD(Conditions);
            IMPL_TYPED_CHILD(Advice);
            IMPL_TYPED_CHILDREN(Statement, m_pos_Signature);
            IMPL_TYPED_CHILDREN(SubjectStatement, m_pos_Signature);
            IMPL_TYPED_CHILDREN(AuthenticationStatement, m_pos_Signature);
            IMPL_TYPED_CHILDREN(AttributeStatement, m_pos_Signature);
            IMPL_TYPED_CHILDREN(AuthorizationDecisionStatement, m_pos_Signature);

        protected:
            void marshallAttributes(DOMElement* domElement) const {
                static const XMLCh MAJORVERSION[] = UNICODE_LITERAL_12(M,a,j,o,r,V,e,r,s,i,o,n);
                domElement->setAttributeNS(nullptr,MAJORVERSION,XML_ONE);
                if (!m_MinorVersion)
                    const_cast<AssertionImpl*>(this)->m_MinorVersion=XMLString::replicate(XML_ONE);
                MARSHALL_INTEGER_ATTRIB(MinorVersion,MINORVERSION,nullptr);
                if (!m_AssertionID)
                    const_cast<AssertionImpl*>(this)->m_AssertionID=SAMLConfig::getConfig().generateIdentifier();
                domElement->setAttributeNS(nullptr, ASSERTIONID_ATTRIB_NAME, m_AssertionID);
                if (*m_MinorVersion!=chDigit_0) {
#ifdef XMLTOOLING_XERCESC_BOOLSETIDATTRIBUTE
                    domElement->setIdAttributeNS(nullptr, ASSERTIONID_ATTRIB_NAME, true);
#else
                    domElement->setIdAttributeNS(nullptr, ASSERTIONID_ATTRIB_NAME);
#endif
                }
                MARSHALL_STRING_ATTRIB(Issuer,ISSUER,nullptr);
                if (!m_IssueInstant) {
                    const_cast<AssertionImpl*>(this)->m_IssueInstantEpoch=time(nullptr);
                    const_cast<AssertionImpl*>(this)->m_IssueInstant=new DateTime(m_IssueInstantEpoch);
                }
                MARSHALL_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,nullptr);
            }

            void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
                PROC_TYPED_CHILD(Conditions,SAML1_NS,false);
                PROC_TYPED_CHILD(Advice,SAML1_NS,false);
                PROC_TYPED_CHILD(Signature,XMLSIG_NS,false);
                PROC_TYPED_CHILDREN(AuthenticationStatement,SAML1_NS,false);
                PROC_TYPED_CHILDREN(AttributeStatement,SAML1_NS,false);
                PROC_TYPED_CHILDREN(AuthorizationDecisionStatement,SAML1_NS,false);
                PROC_TYPED_CHILDREN(SubjectStatement,SAML1_NS,true);
                PROC_TYPED_CHILDREN(Statement,SAML1_NS,true);
                AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
            }

            void unmarshallAttributes(const DOMElement* domElement) {
                // Standard processing, but then we check IDness.
                AbstractXMLObjectUnmarshaller::unmarshallAttributes(domElement);
                if (m_AssertionID && (!m_MinorVersion || *m_MinorVersion!=chDigit_0)) {
#ifdef XMLTOOLING_XERCESC_BOOLSETIDATTRIBUTE
                    const_cast<DOMElement*>(domElement)->setIdAttributeNS(nullptr, ASSERTIONID_ATTRIB_NAME, true);
#else
                    const_cast<DOMElement*>(domElement)->setIdAttributeNS(nullptr, ASSERTIONID_ATTRIB_NAME);
#endif
                }
            }

            void processAttribute(const DOMAttr* attribute) {
                static const XMLCh MAJORVERSION[] = UNICODE_LITERAL_12(M,a,j,o,r,V,e,r,s,i,o,n);
                if (XMLHelper::isNodeNamed(attribute,nullptr,MAJORVERSION)) {
                    if (!XMLString::equals(attribute->getValue(),XML_ONE))
                        throw UnmarshallingException("Assertion has invalid major version.");
                }
                PROC_INTEGER_ATTRIB(MinorVersion,MINORVERSION,nullptr);
                PROC_STRING_ATTRIB(AssertionID,ASSERTIONID,nullptr);
                PROC_STRING_ATTRIB(Issuer,ISSUER,nullptr);
                PROC_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT,nullptr);
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
IMPL_XMLOBJECTBUILDER(AssertionIDReference);
IMPL_XMLOBJECTBUILDER(Attribute);
IMPL_XMLOBJECTBUILDER(AttributeDesignator);
IMPL_XMLOBJECTBUILDER(AttributeStatement);
IMPL_XMLOBJECTBUILDER(AttributeValue);
IMPL_XMLOBJECTBUILDER(Audience);
IMPL_XMLOBJECTBUILDER(AudienceRestrictionCondition);
IMPL_XMLOBJECTBUILDER(AuthenticationStatement);
IMPL_XMLOBJECTBUILDER(AuthorizationDecisionStatement);
IMPL_XMLOBJECTBUILDER(AuthorityBinding);
IMPL_XMLOBJECTBUILDER(Condition);
IMPL_XMLOBJECTBUILDER(Conditions);
IMPL_XMLOBJECTBUILDER(ConfirmationMethod);
IMPL_XMLOBJECTBUILDER(DoNotCacheCondition);
IMPL_XMLOBJECTBUILDER(Evidence);
IMPL_XMLOBJECTBUILDER(NameIdentifier);
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
const XMLCh Assertion::MINORVERSION_ATTRIB_NAME[] = UNICODE_LITERAL_12(M,i,n,o,r,V,e,r,s,i,o,n);
const XMLCh Assertion::ASSERTIONID_ATTRIB_NAME[] =  UNICODE_LITERAL_11(A,s,s,e,r,t,i,o,n,I,D);
const XMLCh Assertion::ISSUER_ATTRIB_NAME[] =       UNICODE_LITERAL_6(I,s,s,u,e,r);
const XMLCh Assertion::ISSUEINSTANT_ATTRIB_NAME[] = UNICODE_LITERAL_12(I,s,s,u,e,I,n,s,t,a,n,t);
const XMLCh AssertionIDReference::LOCAL_NAME[] =    UNICODE_LITERAL_20(A,s,s,e,r,t,i,o,n,I,D,R,e,f,e,r,e,n,c,e);
const XMLCh Attribute::LOCAL_NAME[] =               UNICODE_LITERAL_9(A,t,t,r,i,b,u,t,e);
const XMLCh Attribute::TYPE_NAME[] =                UNICODE_LITERAL_13(A,t,t,r,i,b,u,t,e,T,y,p,e);
const XMLCh AttributeDesignator::LOCAL_NAME[] =     UNICODE_LITERAL_19(A,t,t,r,i,b,u,t,e,D,e,s,i,g,n,a,t,o,r);
const XMLCh AttributeDesignator::TYPE_NAME[] =      UNICODE_LITERAL_23(A,t,t,r,i,b,u,t,e,D,e,s,i,g,n,a,t,o,r,T,y,p,e);
const XMLCh AttributeDesignator::ATTRIBUTENAME_ATTRIB_NAME[] =              UNICODE_LITERAL_13(A,t,t,r,i,b,u,t,e,N,a,m,e);
const XMLCh AttributeDesignator::ATTRIBUTENAMESPACE_ATTRIB_NAME[] =         UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,N,a,m,e,s,p,a,c,e);
const XMLCh AttributeStatement::LOCAL_NAME[] =      UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,S,t,a,t,e,m,e,n,t);
const XMLCh AttributeStatement::TYPE_NAME[] =       UNICODE_LITERAL_22(A,t,t,r,i,b,u,t,e,S,t,a,t,e,m,e,n,t,T,y,p,e);
const XMLCh AttributeValue::LOCAL_NAME[] =          UNICODE_LITERAL_14(A,t,t,r,i,b,u,t,e,V,a,l,u,e);
const XMLCh Audience::LOCAL_NAME[] =                UNICODE_LITERAL_8(A,u,d,i,e,n,c,e);
const XMLCh AudienceRestrictionCondition::LOCAL_NAME[] =    UNICODE_LITERAL_28(A,u,d,i,e,n,c,e,R,e,s,t,r,i,c,t,i,o,n,C,o,n,d,i,t,i,o,n);
const XMLCh AudienceRestrictionCondition::TYPE_NAME[] =     UNICODE_LITERAL_32(A,u,d,i,e,n,c,e,R,e,s,t,r,i,c,t,i,o,n,C,o,n,d,i,t,i,o,n,T,y,p,e);
const XMLCh AuthenticationStatement::LOCAL_NAME[] = UNICODE_LITERAL_23(A,u,t,h,e,n,t,i,c,a,t,i,o,n,S,t,a,t,e,m,e,n,t);
const XMLCh AuthenticationStatement::TYPE_NAME[] =  UNICODE_LITERAL_27(A,u,t,h,e,n,t,i,c,a,t,i,o,n,S,t,a,t,e,m,e,n,t,T,y,p,e);
const XMLCh AuthenticationStatement::AUTHENTICATIONMETHOD_ATTRIB_NAME[] =   UNICODE_LITERAL_20(A,u,t,h,e,n,t,i,c,a,t,i,o,n,M,e,t,h,o,d);
const XMLCh AuthenticationStatement::AUTHENTICATIONINSTANT_ATTRIB_NAME[] =  UNICODE_LITERAL_21(A,u,t,h,e,n,t,i,c,a,t,i,o,n,I,n,s,t,a,n,t);
const XMLCh AuthorityBinding::LOCAL_NAME[] =        UNICODE_LITERAL_16(A,u,t,h,o,r,i,t,y,B,i,n,d,i,n,g);
const XMLCh AuthorityBinding::TYPE_NAME[] =         UNICODE_LITERAL_20(A,u,t,h,o,r,i,t,y,B,i,n,d,i,n,g,T,y,p,e);
const XMLCh AuthorityBinding::AUTHORITYKIND_ATTRIB_NAME[] = UNICODE_LITERAL_13(A,u,t,h,o,r,i,t,y,K,i,n,d);
const XMLCh AuthorityBinding::LOCATION_ATTRIB_NAME[] =      UNICODE_LITERAL_8(L,o,c,a,t,i,o,n);
const XMLCh AuthorityBinding::BINDING_ATTRIB_NAME[] =       UNICODE_LITERAL_7(B,i,n,d,i,n,g);
const XMLCh AuthorizationDecisionStatement::LOCAL_NAME[] =  UNICODE_LITERAL_30(A,u,t,h,o,r,i,z,a,t,i,o,n,D,e,c,i,s,i,o,n,S,t,a,t,e,m,e,n,t);
const XMLCh AuthorizationDecisionStatement::TYPE_NAME[] =   UNICODE_LITERAL_34(A,u,t,h,o,r,i,z,a,t,i,o,n,D,e,c,i,s,i,o,n,S,t,a,t,e,m,e,n,t,T,y,p,e);
const XMLCh AuthorizationDecisionStatement::RESOURCE_ATTRIB_NAME[] =        UNICODE_LITERAL_8(R,e,s,o,u,r,c,e);
const XMLCh AuthorizationDecisionStatement::DECISION_ATTRIB_NAME[] =        UNICODE_LITERAL_8(D,e,c,i,s,i,o,n);
const XMLCh AuthorizationDecisionStatement::DECISION_PERMIT[] =             UNICODE_LITERAL_6(P,e,r,m,i,t);
const XMLCh AuthorizationDecisionStatement::DECISION_DENY[] =               UNICODE_LITERAL_4(D,e,n,y);
const XMLCh AuthorizationDecisionStatement::DECISION_INDETERMINATE[] =      UNICODE_LITERAL_13(I,n,d,e,t,e,r,m,i,n,a,t,e);
const XMLCh Condition::LOCAL_NAME[] =               UNICODE_LITERAL_9(C,o,n,d,i,t,i,o,n);
const XMLCh Conditions::LOCAL_NAME[] =              UNICODE_LITERAL_10(C,o,n,d,i,t,i,o,n,s);
const XMLCh Conditions::TYPE_NAME[] =               UNICODE_LITERAL_14(C,o,n,d,i,t,i,o,n,s,T,y,p,e);
const XMLCh Conditions::NOTBEFORE_ATTRIB_NAME[] =   UNICODE_LITERAL_9(N,o,t,B,e,f,o,r,e);
const XMLCh Conditions::NOTONORAFTER_ATTRIB_NAME[] =UNICODE_LITERAL_12(N,o,t,O,n,O,r,A,f,t,e,r);
const XMLCh ConfirmationMethod::LOCAL_NAME[] =      UNICODE_LITERAL_18(C,o,n,f,i,r,m,a,t,i,o,n,M,e,t,h,o,d);
const XMLCh DoNotCacheCondition::LOCAL_NAME[] =     UNICODE_LITERAL_19(D,o,N,o,t,C,a,c,h,e,C,o,n,d,i,t,i,o,n);
const XMLCh DoNotCacheCondition::TYPE_NAME[] =      UNICODE_LITERAL_23(D,o,N,o,t,C,a,c,h,e,C,o,n,d,i,t,i,o,n,T,y,p,e);
const XMLCh Evidence::LOCAL_NAME[] =                UNICODE_LITERAL_8(E,v,i,d,e,n,c,e);
const XMLCh Evidence::TYPE_NAME[] =                 UNICODE_LITERAL_12(E,v,i,d,e,n,c,e,T,y,p,e);
const XMLCh NameIdentifier::LOCAL_NAME[] =          UNICODE_LITERAL_14(N,a,m,e,I,d,e,n,t,i,f,i,e,r);
const XMLCh NameIdentifier::TYPE_NAME[] =           UNICODE_LITERAL_18(N,a,m,e,I,d,e,n,t,i,f,i,e,r,T,y,p,e);
const XMLCh NameIdentifier::NAMEQUALIFIER_ATTRIB_NAME[] =   UNICODE_LITERAL_13(N,a,m,e,Q,u,a,l,i,f,i,e,r);
const XMLCh NameIdentifier::FORMAT_ATTRIB_NAME[] =  UNICODE_LITERAL_6(F,o,r,m,a,t);
const XMLCh Statement::LOCAL_NAME[] =               UNICODE_LITERAL_9(S,t,a,t,e,m,e,n,t);
const XMLCh Subject::LOCAL_NAME[] =                 UNICODE_LITERAL_7(S,u,b,j,e,c,t);
const XMLCh Subject::TYPE_NAME[] =                  UNICODE_LITERAL_11(S,u,b,j,e,c,t,T,y,p,e);
const XMLCh SubjectConfirmation::LOCAL_NAME[] =     UNICODE_LITERAL_19(S,u,b,j,e,c,t,C,o,n,f,i,r,m,a,t,i,o,n);
const XMLCh SubjectConfirmation::TYPE_NAME[] =      UNICODE_LITERAL_23(S,u,b,j,e,c,t,C,o,n,f,i,r,m,a,t,i,o,n,T,y,p,e);
const XMLCh SubjectConfirmationData::LOCAL_NAME[] = UNICODE_LITERAL_23(S,u,b,j,e,c,t,C,o,n,f,i,r,m,a,t,i,o,n,D,a,t,a);
const XMLCh SubjectLocality::LOCAL_NAME[] =         UNICODE_LITERAL_15(S,u,b,j,e,c,t,L,o,c,a,l,i,t,y);
const XMLCh SubjectLocality::TYPE_NAME[] =          UNICODE_LITERAL_19(S,u,b,j,e,c,t,L,o,c,a,l,i,t,y,T,y,p,e);
const XMLCh SubjectLocality::IPADDRESS_ATTRIB_NAME[] =      UNICODE_LITERAL_9(I,P,A,d,d,r,e,s,s);
const XMLCh SubjectLocality::DNSADDRESS_ATTRIB_NAME[] =     UNICODE_LITERAL_10(D,N,S,A,d,d,r,e,s,s);
const XMLCh SubjectStatement::LOCAL_NAME[] =        UNICODE_LITERAL_16(S,u,b,j,e,c,t,S,t,a,t,e,m,e,n,t);

const XMLCh NameIdentifier::UNSPECIFIED[] = // urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_u, chLatin_n, chLatin_s, chLatin_p, chLatin_e, chLatin_c, chLatin_i, chLatin_f, chLatin_i, chLatin_e, chLatin_d, chLatin_d, chNull
};

const XMLCh NameIdentifier::EMAIL[] = // urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_e, chLatin_m, chLatin_a, chLatin_i, chLatin_l, chLatin_A, chLatin_d, chLatin_d, chLatin_r, chLatin_e, chLatin_s, chLatin_s, chNull
};

const XMLCh NameIdentifier::X509_SUBJECT[] = // urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
  chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
  chLatin_X, chDigit_5, chDigit_0, chDigit_9, chLatin_S, chLatin_u, chLatin_b, chLatin_j, chLatin_e, chLatin_c, chLatin_t,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull
};

const XMLCh NameIdentifier::WIN_DOMAIN_QUALIFIED[] = // urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName
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

const XMLCh SubjectConfirmation::ARTIFACT01[] = // urn:oasis:names:tc:SAML:1.0:cm:artifact-01
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_c, chLatin_m, chColon, chLatin_a, chLatin_r, chLatin_t, chLatin_i, chLatin_f, chLatin_a, chLatin_c, chLatin_t,
      chDash, chDigit_0, chDigit_1, chNull
};

const XMLCh SubjectConfirmation::ARTIFACT[] = // urn:oasis:names:tc:SAML:1.0:cm:artifact
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_c, chLatin_m, chColon, chLatin_a, chLatin_r, chLatin_t, chLatin_i, chLatin_f, chLatin_a, chLatin_c, chLatin_t, chNull
};

const XMLCh SubjectConfirmation::BEARER[] = // urn:oasis:names:tc:SAML:1.0:cm:bearer
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_c, chLatin_m, chColon, chLatin_b, chLatin_e, chLatin_a, chLatin_r, chLatin_e, chLatin_r, chNull
};

const XMLCh SubjectConfirmation::HOLDER_KEY[] = // urn:oasis:names:tc:SAML:1.0:cm:holder-of-key
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_c, chLatin_m, chColon, chLatin_h, chLatin_o, chLatin_l, chLatin_d, chLatin_e, chLatin_r, chDash,
      chLatin_o, chLatin_f, chDash, chLatin_k, chLatin_e, chLatin_y, chNull
};

const XMLCh SubjectConfirmation::SENDER_VOUCHES[] = // urn:oasis:names:tc:SAML:1.0:cm:sender-vouches
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
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
