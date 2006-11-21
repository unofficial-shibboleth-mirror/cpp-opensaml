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
 * @file saml/saml2/core/Assertions.h
 * 
 * XMLObjects representing the SAML 2.0 Assertions schema
 */

#ifndef __saml2_assertions_h__
#define __saml2_assertions_h__

#include <saml/RootObject.h>
#include <saml/util/SAMLConstants.h>

#include <xmltooling/AttributeExtensibleXMLObject.h>
#include <xmltooling/ElementProxy.h>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/encryption/Encryption.h>
#include <xmltooling/signature/KeyResolver.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/DateTime.h>

#define DECL_SAML2OBJECTBUILDER(cname) \
    DECL_XMLOBJECTBUILDER(SAML_API,cname,samlconstants::SAML20_NS,samlconstants::SAML20_PREFIX)

namespace opensaml {

    /**
     * @namespace opensaml::saml2
     * SAML 2.0 assertion namespace
     */
    namespace saml2 {
        
        // Forward references
        class SAML_API Assertion;
        class SAML_API EncryptedAssertion;
        
        DECL_XMLOBJECT_SIMPLE(SAML_API,AssertionIDRef,AssertionID,SAML 2.0 AssertionIDRef element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,AssertionURIRef,AssertionURI,SAML 2.0 AssertionURIRef element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,Audience,AudienceURI,SAML 2.0 Audience element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,AuthnContextClassRef,Reference,SAML 2.0 AuthnContextClassRef element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,AuthnContextDeclRef,Reference,SAML 2.0 AuthnContextDeclRef element);
        DECL_XMLOBJECT_SIMPLE(SAML_API,AuthenticatingAuthority,ID,SAML 2.0 AuthenticatingAuthority element);

        BEGIN_XMLOBJECT(SAML_API,EncryptedElementType,xmltooling::XMLObject,SAML 2.0 EncryptedElementType type);
            DECL_TYPED_FOREIGN_CHILD(EncryptedData,xmlencryption);
            DECL_TYPED_FOREIGN_CHILDREN(EncryptedKey,xmlencryption);
            /** EncryptedElementType local name */
            static const XMLCh TYPE_NAME[];
            
            /**
             * Decrypts the element using a standard approach based on a wrapped decryption key
             * inside the message. The key decryption key should be supplied using the provided
             * resolver. The recipient name may be used when multiple encrypted keys are found.
             * The object returned will be unmarshalled around the decrypted DOM element, but the
             * DOM itself will be released. 
             * 
             * @param KEKresolver   resolver supplying key decryption key
             * @param recipient     identifier naming the recipient (the entity performing the decryption)
             * @return  the decrypted and unmarshalled object
             */
            virtual xmltooling::XMLObject* decrypt(xmlsignature::KeyResolver* KEKresolver, const XMLCh* recipient) const=0;
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,EncryptedID,EncryptedElementType,SAML 2.0 EncryptedID element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,BaseID,xmltooling::XMLObject,SAML 2.0 BaseID abstract element);
            DECL_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER);
            DECL_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,NameIDType,xmltooling::XMLObject,SAML 2.0 NameIDType type);
            DECL_STRING_ATTRIB(NameQualifier,NAMEQUALIFIER);
            DECL_STRING_ATTRIB(SPNameQualifier,SPNAMEQUALIFIER);
            DECL_STRING_ATTRIB(Format,FORMAT);
            DECL_STRING_ATTRIB(SPProvidedID,SPPROVIDEDID);
            DECL_SIMPLE_CONTENT(Name);
            /** NameIDType local name */
            static const XMLCh TYPE_NAME[];
            /** Unspecified name format ID */
            static const XMLCh UNSPECIFIED[];
            /** Email address name format ID */
            static const XMLCh EMAIL[];
            /** X.509 subject name format ID */
            static const XMLCh X509_SUBJECT[];
            /** Windows domain qualified name format ID */
            static const XMLCh WIN_DOMAIN_QUALIFIED[];
            /** Kerberos principal name format ID */
            static const XMLCh KERBEROS[];
            /** Entity identifier name format ID */
            static const XMLCh ENTITY[];
            /** Persistent identifier name format ID */
            static const XMLCh PERSISTENT[];
            /** Transient identifier name format ID */
            static const XMLCh TRANSIENT[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,NameID,NameIDType,SAML 2.0 NameID element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Issuer,NameIDType,SAML 2.0 Issuer element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Condition,xmltooling::XMLObject,SAML 2.0 Condition element);
        END_XMLOBJECT;
        
        BEGIN_XMLOBJECT(SAML_API,AudienceRestriction,Condition,SAML 2.0 AudienceRestriction element);
            DECL_TYPED_CHILDREN(Audience);
            /** AudienceRestrictionType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,OneTimeUse,Condition,SAML 2.0 OneTimeUse element);
            /** OneTimeUseType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,ProxyRestriction,Condition,SAML 2.0 ProxyRestriction element);
            DECL_INTEGER_ATTRIB(Count,COUNT);
            DECL_TYPED_CHILDREN(Audience);
            /** ProxyRestrictionType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Conditions,xmltooling::XMLObject,SAML 2.0 Conditions element);
            DECL_DATETIME_ATTRIB(NotBefore,NOTBEFORE);
            DECL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER);
            DECL_TYPED_CHILDREN(AudienceRestriction);
            DECL_TYPED_CHILDREN(OneTimeUse);
            DECL_TYPED_CHILDREN(ProxyRestriction);
            DECL_TYPED_CHILDREN(Condition);
            /** ConditionsType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT2(SAML_API,SubjectConfirmationData,xmltooling::ElementProxy,xmltooling::AttributeExtensibleXMLObject,SAML 2.0 SubjectConfirmationData element);
            DECL_DATETIME_ATTRIB(NotBefore,NOTBEFORE);
            DECL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER);
            DECL_STRING_ATTRIB(Recipient,RECIPIENT);
            DECL_STRING_ATTRIB(InResponseTo,INRESPONSETO);
            DECL_STRING_ATTRIB(Address,ADDRESS);
            DECL_SIMPLE_CONTENT(Data);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,KeyInfoConfirmationDataType,xmltooling::AttributeExtensibleXMLObject,SAML 2.0 KeyInfoConfirmationDataType type);
            DECL_DATETIME_ATTRIB(NotBefore,NOTBEFORE);
            DECL_DATETIME_ATTRIB(NotOnOrAfter,NOTONORAFTER);
            DECL_STRING_ATTRIB(Recipient,RECIPIENT);
            DECL_STRING_ATTRIB(InResponseTo,INRESPONSETO);
            DECL_STRING_ATTRIB(Address,ADDRESS);
            DECL_TYPED_FOREIGN_CHILDREN(KeyInfo,xmlsignature);
            /** KeyInfoConfirmationDataType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;
        
        BEGIN_XMLOBJECT(SAML_API,SubjectConfirmation,xmltooling::XMLObject,SAML 2.0 SubjectConfirmation element);
            DECL_STRING_ATTRIB(Method,METHOD);
            DECL_TYPED_CHILD(BaseID);
            DECL_TYPED_CHILD(NameID);
            DECL_TYPED_CHILD(EncryptedID);
            DECL_XMLOBJECT_CHILD(SubjectConfirmationData);
            DECL_TYPED_CHILD(KeyInfoConfirmationDataType);
            /** SubjectConfirmationType local name */
            static const XMLCh TYPE_NAME[];
            /** Bearer confirmation method */
            static const XMLCh BEARER[];
            /** Holder of key confirmation method */
            static const XMLCh HOLDER_KEY[];
            /** Sender vouches confirmation method */
            static const XMLCh SENDER_VOUCHES[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Subject,xmltooling::XMLObject,SAML 2.0 Subject element);
            DECL_TYPED_CHILD(BaseID);
            DECL_TYPED_CHILD(NameID);
            DECL_TYPED_CHILD(EncryptedID);
            DECL_TYPED_CHILDREN(SubjectConfirmation);
            /** SubjectType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Statement,xmltooling::XMLObject,SAML 2.0 Statement element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,SubjectLocality,xmltooling::XMLObject,SAML 2.0 SubjectLocality element);
            DECL_STRING_ATTRIB(Address,ADDRESS);
            DECL_STRING_ATTRIB(DNSName,DNSNAME);
            /** SubjectLocalityType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT2(SAML_API,AuthnContextDecl,xmltooling::ElementProxy,xmltooling::AttributeExtensibleXMLObject,SAML 2.0 AuthnContextDecl element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnContext,xmltooling::XMLObject,SAML 2.0 AuthnContext element);
            DECL_TYPED_CHILD(AuthnContextClassRef);
            DECL_XMLOBJECT_CHILD(AuthnContextDecl);
            DECL_TYPED_CHILD(AuthnContextDeclRef);
            DECL_TYPED_CHILDREN(AuthenticatingAuthority);
            /** AuthnContextType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthnStatement,Statement,SAML 2.0 AuthnStatement element);
            DECL_DATETIME_ATTRIB(AuthnInstant,AUTHNINSTANT);
            DECL_STRING_ATTRIB(SessionIndex,SESSIONINDEX);
            DECL_DATETIME_ATTRIB(SessionNotOnOrAfter,SESSIONNOTONORAFTER);
            DECL_TYPED_CHILD(SubjectLocality);
            DECL_TYPED_CHILD(AuthnContext);
            /** AuthnStatementType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Action,xmltooling::XMLObject,SAML 2.0 Action element);
            DECL_STRING_ATTRIB(Namespace,NAMESPACE);
            DECL_SIMPLE_CONTENT(Action);
            /** ActionType local name */
            static const XMLCh TYPE_NAME[];
            /** Read/Write/Execute/Delete/Control Action Namespace */
            static const XMLCh RWEDC_NEG_ACTION_NAMESPACE[];
            /** Read/Write/Execute/Delete/Control with Negation Action Namespace */
            static const XMLCh RWEDC_ACTION_NAMESPACE[];
            /** Get/Head/Put/Post Action Namespace */
            static const XMLCh GHPP_ACTION_NAMESPACE[];
            /** UNIX File Permissions Action Namespace */
            static const XMLCh UNIX_ACTION_NAMESPACE[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Evidence,xmltooling::XMLObject,SAML 2.0 Evidence element);
            DECL_TYPED_CHILDREN(AssertionIDRef);
            DECL_TYPED_CHILDREN(AssertionURIRef);
            DECL_TYPED_CHILDREN(Assertion);
            DECL_TYPED_CHILDREN(EncryptedAssertion);
            /** EvidenceType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AuthzDecisionStatement,Statement,SAML 2.0 AuthzDecisionStatement element);
            DECL_STRING_ATTRIB(Resource,RESOURCE);
            DECL_STRING_ATTRIB(Decision,DECISION);
            DECL_TYPED_CHILDREN(Action);
            DECL_TYPED_CHILD(Evidence);
            /** AuthzDecisionStatementType local name */
            static const XMLCh TYPE_NAME[];
            /** Permit Decision */
            static const XMLCh DECISION_PERMIT[];
            /** Deny Decision */
            static const XMLCh DECISION_DENY[];
            /** Indeterminate Decision */
            static const XMLCh DECISION_INDETERMINATE[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT2(SAML_API,AttributeValue,xmltooling::ElementProxy,xmltooling::AttributeExtensibleXMLObject,SAML 2.0 AttributeValue element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Attribute,xmltooling::AttributeExtensibleXMLObject,SAML 2.0 Attribute element);
            DECL_STRING_ATTRIB(Name,NAME);
            DECL_STRING_ATTRIB(NameFormat,NAMEFORMAT);
            DECL_STRING_ATTRIB(FriendlyName,FRIENDLYNAME);
            DECL_XMLOBJECT_CHILDREN(AttributeValue);
            /** AttributeType local name */
            static const XMLCh TYPE_NAME[];
            /** Unspecified attribute name format ID */
            static const XMLCh UNSPECIFIED[];
            /** URI reference attribute name format ID */
            static const XMLCh URI_REFERENCE[];
            /** Basic attribute name format ID */
            static const XMLCh BASIC[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,EncryptedAttribute,EncryptedElementType,SAML 2.0 EncryptedAttribute element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,AttributeStatement,Statement,SAML 2.0 AttributeStatement element);
            DECL_TYPED_CHILDREN(Attribute);
            DECL_TYPED_CHILDREN(EncryptedAttribute);
            /** AttributeStatementType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,EncryptedAssertion,EncryptedElementType,SAML 2.0 EncryptedAssertion element);
        END_XMLOBJECT;

        BEGIN_XMLOBJECT(SAML_API,Advice,xmltooling::XMLObject,SAML 2.0 Advice element);
            DECL_TYPED_CHILDREN(AssertionIDRef);
            DECL_TYPED_CHILDREN(AssertionURIRef);
            DECL_TYPED_CHILDREN(Assertion);
            DECL_TYPED_CHILDREN(EncryptedAssertion);
            DECL_XMLOBJECT_CHILDREN(Other);
            /** AdviceType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        /**
         * SAML 2.0 assertion or protocol message.
         */
        class SAML_API RootObject : virtual public opensaml::RootObject
        {
        protected:
            RootObject() {}
        public:
            virtual ~RootObject() {}
            
            /** Gets the Version attribute. */
            virtual const XMLCh* getVersion() const=0;
            
            /** Gets the Issuer. */
            virtual Issuer* getIssuer() const=0;
        };

        BEGIN_XMLOBJECT(SAML_API,Assertion,saml2::RootObject,SAML 2.0 Assertion element);
            DECL_INHERITED_STRING_ATTRIB(Version,VER);
            DECL_INHERITED_STRING_ATTRIB(ID,ID);
            DECL_INHERITED_DATETIME_ATTRIB(IssueInstant,ISSUEINSTANT);
            DECL_INHERITED_TYPED_CHILD(Issuer);
            DECL_INHERITED_TYPED_FOREIGN_CHILD(Signature,xmlsignature);
            DECL_TYPED_CHILD(Subject);
            DECL_TYPED_CHILD(Conditions);
            DECL_TYPED_CHILD(Advice);
            DECL_TYPED_CHILDREN(Statement);
            DECL_TYPED_CHILDREN(AuthnStatement);
            DECL_TYPED_CHILDREN(AttributeStatement);
            DECL_TYPED_CHILDREN(AuthzDecisionStatement);
            /** AssertionType local name */
            static const XMLCh TYPE_NAME[];
        END_XMLOBJECT;

        DECL_SAML2OBJECTBUILDER(Action);
        DECL_SAML2OBJECTBUILDER(Advice);
        DECL_SAML2OBJECTBUILDER(Assertion);
        DECL_SAML2OBJECTBUILDER(AssertionIDRef);
        DECL_SAML2OBJECTBUILDER(AssertionURIRef);
        DECL_SAML2OBJECTBUILDER(Attribute);
        DECL_SAML2OBJECTBUILDER(AttributeStatement);
        DECL_SAML2OBJECTBUILDER(AttributeValue);
        DECL_SAML2OBJECTBUILDER(Audience);
        DECL_SAML2OBJECTBUILDER(AudienceRestriction);
        DECL_SAML2OBJECTBUILDER(AuthenticatingAuthority);
        DECL_SAML2OBJECTBUILDER(AuthnContext);
        DECL_SAML2OBJECTBUILDER(AuthnContextClassRef);
        DECL_SAML2OBJECTBUILDER(AuthnContextDecl);
        DECL_SAML2OBJECTBUILDER(AuthnContextDeclRef);
        DECL_SAML2OBJECTBUILDER(AuthnStatement);
        DECL_SAML2OBJECTBUILDER(AuthzDecisionStatement);
        DECL_SAML2OBJECTBUILDER(Conditions);
        DECL_SAML2OBJECTBUILDER(EncryptedAssertion);
        DECL_SAML2OBJECTBUILDER(EncryptedAttribute);
        DECL_SAML2OBJECTBUILDER(EncryptedID);
        DECL_SAML2OBJECTBUILDER(Evidence);
        DECL_SAML2OBJECTBUILDER(Issuer);
        DECL_SAML2OBJECTBUILDER(NameID);
        DECL_SAML2OBJECTBUILDER(OneTimeUse);
        DECL_SAML2OBJECTBUILDER(ProxyRestriction);
        DECL_SAML2OBJECTBUILDER(Subject);
        DECL_SAML2OBJECTBUILDER(SubjectConfirmation);
        DECL_SAML2OBJECTBUILDER(SubjectConfirmationData);
        DECL_SAML2OBJECTBUILDER(SubjectLocality);
        
        /**
         * Builder for NameIDType objects.
         * 
         * This is customized to force the element name to be specified.
         */
        class SAML_API NameIDTypeBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~NameIDTypeBuilder() {}
            /** Builder that allows element/type override. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual NameIDType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL
                ) const;
        
            /** Singleton builder. */
            static NameIDType* buildNameIDType(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL) {
                const NameIDTypeBuilder* b = dynamic_cast<const NameIDTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20_NS,NameIDType::TYPE_NAME))
                    );
                if (b) {
                    xmltooling::QName schemaType(samlconstants::SAML20_NS,NameIDType::TYPE_NAME,samlconstants::SAML20_PREFIX);
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject(nsURI, localName, prefix, &schemaType);
#else
                    return dynamic_cast<NameIDType*>(b->buildObject(nsURI, localName, prefix, &schemaType));
#endif
                }
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for NameIDType.");
            }
        };

        /**
         * Builder for KeyInfoConfirmationDataType objects.
         * 
         * This is customized to return a SubjectConfirmationData element with an
         * xsi:type of KeyInfoConfirmationDataType.
         */
        class SAML_API KeyInfoConfirmationDataTypeBuilder : public xmltooling::XMLObjectBuilder {
        public:
            virtual ~KeyInfoConfirmationDataTypeBuilder() {}
            /** Default builder. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual KeyInfoConfirmationDataType* buildObject() const {
#else
            virtual xmltooling::XMLObject* buildObject() const {
#endif
                xmltooling::QName schemaType(
                    samlconstants::SAML20_NS,KeyInfoConfirmationDataType::TYPE_NAME,samlconstants::SAML20_PREFIX
                    );
                return buildObject(
                    samlconstants::SAML20_NS,KeyInfoConfirmationDataType::LOCAL_NAME,samlconstants::SAML20_PREFIX,&schemaType
                    );
            }
            /** Builder that allows element/type override. */
#ifdef HAVE_COVARIANT_RETURNS
            virtual KeyInfoConfirmationDataType* buildObject(
#else
            virtual xmltooling::XMLObject* buildObject(
#endif
                const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL
                ) const;
        
            /** Singleton builder. */
            static KeyInfoConfirmationDataType* buildKeyInfoConfirmationDataType() {
                const KeyInfoConfirmationDataTypeBuilder* b = dynamic_cast<const KeyInfoConfirmationDataTypeBuilder*>(
                    XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20_NS,KeyInfoConfirmationDataType::TYPE_NAME))
                    );
                if (b)
#ifdef HAVE_COVARIANT_RETURNS
                    return b->buildObject();
#else
                    return dynamic_cast<KeyInfoConfirmationDataType*>(b->buildObject());
#endif
                throw xmltooling::XMLObjectException("Unable to obtain typed builder for KeyInfoConfirmationDataType.");
            }
        };
        
        /**
         * Registers builders and validators for SAML 2.0 Assertion classes into the runtime.
         */
        void SAML_API registerAssertionClasses();
    };
};

#endif /* __saml2_assertions_h__ */
