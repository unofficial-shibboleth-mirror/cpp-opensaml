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
 * SignatureMetadataFilter.cpp
 *
 * Filters out unsigned or mis-signed elements.
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"
#include "signature/SignatureProfileValidator.h"

#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/security/SignatureTrustEngine.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/signature/SignatureValidator.h>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {

        class SAML_DLLLOCAL DummyCredentialResolver : public CredentialResolver
        {
        public:
            DummyCredentialResolver() {}
            ~DummyCredentialResolver() {}

            Lockable* lock() {return this;}
            void unlock() {}

            const Credential* resolve(const CredentialCriteria* criteria=nullptr) const {return nullptr;}
            vector<const Credential*>::size_type resolve(
                vector<const Credential*>& results, const CredentialCriteria* criteria=nullptr
                ) const {return 0;}
        };

        class SAML_DLLLOCAL SignatureMetadataFilter : public MetadataFilter
        {
        public:
            SignatureMetadataFilter(const DOMElement* e);
            ~SignatureMetadataFilter() {
                delete m_credResolver;
                delete m_trust;
            }

            const char* getId() const { return SIGNATURE_METADATA_FILTER; }
            void doFilter(XMLObject& xmlObject) const;

        private:
            void doFilter(EntitiesDescriptor& entities, bool rootObject=false) const;
            void doFilter(EntityDescriptor& entity, bool rootObject=false) const;
            void verifySignature(Signature* sig, const XMLCh* peerName) const;

            bool m_verifyRoles,m_verifyName;
            CredentialResolver* m_credResolver;
            SignatureTrustEngine* m_trust;
            SignatureProfileValidator m_profileValidator;
            Category& m_log;
        };

        MetadataFilter* SAML_DLLLOCAL SignatureMetadataFilterFactory(const DOMElement* const & e)
        {
            return new SignatureMetadataFilter(e);
        }

    };
};

static const XMLCh _TrustEngine[] =         UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
static const XMLCh _CredentialResolver[] =  UNICODE_LITERAL_18(C,r,e,d,e,n,t,i,a,l,R,e,s,o,l,v,e,r);
static const XMLCh type[] =                 UNICODE_LITERAL_4(t,y,p,e);
static const XMLCh certificate[] =          UNICODE_LITERAL_11(c,e,r,t,i,f,i,c,a,t,e);
static const XMLCh Certificate[] =          UNICODE_LITERAL_11(C,e,r,t,i,f,i,c,a,t,e);
static const XMLCh Path[] =                 UNICODE_LITERAL_4(P,a,t,h);
static const XMLCh verifyRoles[] =          UNICODE_LITERAL_11(v,e,r,i,f,y,R,o,l,e,s);
static const XMLCh verifyName[] =           UNICODE_LITERAL_10(v,e,r,i,f,y,N,a,m,e);

SignatureMetadataFilter::SignatureMetadataFilter(const DOMElement* e)
    : m_verifyRoles(false), m_verifyName(true), m_credResolver(nullptr), m_trust(nullptr), m_log(Category::getInstance(SAML_LOGCAT".MetadataFilter.Signature"))
{
    const XMLCh* flag = e ? e->getAttributeNS(nullptr,verifyRoles) : nullptr;
    m_verifyRoles = (flag && (*flag == chLatin_t || *flag == chDigit_1));

    flag = e ? e->getAttributeNS(nullptr,verifyName) : nullptr;
    m_verifyName = !(flag && (*flag == chLatin_f || *flag == chDigit_0));

    if (e && e->hasAttributeNS(nullptr,certificate)) {
        // Use a file-based credential resolver rooted here.
        m_credResolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER,e);
        return;
    }

    DOMElement* sub = e ? XMLHelper::getFirstChildElement(e, _CredentialResolver) : nullptr;
    auto_ptr_char t(sub ? sub->getAttributeNS(nullptr,type) : nullptr);
    if (t.get()) {
        m_credResolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(t.get(),sub);
        return;
    }

    sub = e ? XMLHelper::getFirstChildElement(e, _TrustEngine) : nullptr;
    auto_ptr_char t2(sub ? sub->getAttributeNS(nullptr,type) : nullptr);
    if (t2.get()) {
        TrustEngine* trust = XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(t2.get(),sub);
        if (!(m_trust = dynamic_cast<SignatureTrustEngine*>(trust))) {
            delete trust;
            throw MetadataFilterException("TrustEngine-based SignatureMetadataFilter requires a SignatureTrustEngine plugin.");
        }
        return;
    }

    throw MetadataFilterException("SignatureMetadataFilter configuration requires <CredentialResolver> or <TrustEngine> element.");
}

void SignatureMetadataFilter::doFilter(XMLObject& xmlObject) const
{
#ifdef _DEBUG
    NDC ndc("doFilter");
#endif

    try {
        EntitiesDescriptor& entities = dynamic_cast<EntitiesDescriptor&>(xmlObject);
        doFilter(entities, true);
        return;
    }
    catch (bad_cast) {
    }
    catch (exception& ex) {
        m_log.warn("filtering out group at root of instance after failed signature check: %s", ex.what());
        throw MetadataFilterException("SignatureMetadataFilter unable to verify signature at root of metadata instance.");
    }

    try {
        EntityDescriptor& entity = dynamic_cast<EntityDescriptor&>(xmlObject);
        doFilter(entity, true);
        return;
    }
    catch (bad_cast) {
    }
    catch (exception& ex) {
        m_log.warn("filtering out entity at root of instance after failed signature check: %s", ex.what());
        throw MetadataFilterException("SignatureMetadataFilter unable to verify signature at root of metadata instance.");
    }

    throw MetadataFilterException("SignatureMetadataFilter was given an improper metadata instance to filter.");
}

void SignatureMetadataFilter::doFilter(EntitiesDescriptor& entities, bool rootObject) const
{
    Signature* sig = entities.getSignature();
    if (!sig && rootObject)
        throw MetadataFilterException("Root metadata element was unsigned.");
    verifySignature(sig, entities.getName());

    VectorOf(EntityDescriptor) v=entities.getEntityDescriptors();
    for (VectorOf(EntityDescriptor)::size_type i=0; i<v.size(); ) {
        try {
            doFilter(*(v[i]));
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(v[i]->getEntityID());
            m_log.warn("filtering out entity (%s) after failed signature check: %s", id.get(), e.what());
            v.erase(v.begin() + i);
        }
    }

    VectorOf(EntitiesDescriptor) w=entities.getEntitiesDescriptors();
    for (VectorOf(EntitiesDescriptor)::size_type j=0; j<w.size(); ) {
        try {
            doFilter(*w[j], false);
            j++;
        }
        catch (exception& e) {
            auto_ptr_char name(w[j]->getName());
            m_log.warn("filtering out group (%s) after failed signature check: %s", name.get(), e.what());
            w.erase(w.begin() + j);
        }
    }
}

void SignatureMetadataFilter::doFilter(EntityDescriptor& entity, bool rootObject) const
{
    Signature* sig = entity.getSignature();
    if (!sig && rootObject)
        throw MetadataFilterException("Root metadata element was unsigned.");
    verifySignature(sig, entity.getEntityID());

    if (!m_verifyRoles)
        return;

    VectorOf(IDPSSODescriptor) idp=entity.getIDPSSODescriptors();
    for (VectorOf(IDPSSODescriptor)::size_type i=0; i<idp.size(); ) {
        try {
            verifySignature(idp[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out IDPSSODescriptor for entity (%s) after failed signature check: %s", id.get(), e.what()
                );
            idp.erase(idp.begin() + i);
        }
    }

    VectorOf(SPSSODescriptor) sp=entity.getSPSSODescriptors();
    for (VectorOf(SPSSODescriptor)::size_type i=0; i<sp.size(); ) {
        try {
            verifySignature(sp[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out SPSSODescriptor for entity (%s) after failed signature check: %s", id.get(), e.what()
                );
            sp.erase(sp.begin() + i);
        }
    }

    VectorOf(AuthnAuthorityDescriptor) authn=entity.getAuthnAuthorityDescriptors();
    for (VectorOf(AuthnAuthorityDescriptor)::size_type i=0; i<authn.size(); ) {
        try {
            verifySignature(authn[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out AuthnAuthorityDescriptor for entity (%s) after failed signature check: %s", id.get(), e.what()
                );
            authn.erase(authn.begin() + i);
        }
    }

    VectorOf(AttributeAuthorityDescriptor) aa=entity.getAttributeAuthorityDescriptors();
    for (VectorOf(AttributeAuthorityDescriptor)::size_type i=0; i<aa.size(); ) {
        try {
            verifySignature(aa[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out AttributeAuthorityDescriptor for entity (%s) after failed signature check: %s", id.get(), e.what()
                );
            aa.erase(aa.begin() + i);
        }
    }

    VectorOf(PDPDescriptor) pdp=entity.getPDPDescriptors();
    for (VectorOf(AuthnAuthorityDescriptor)::size_type i=0; i<pdp.size(); ) {
        try {
            verifySignature(pdp[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out PDPDescriptor for entity (%s) after failed signature check: %s", id.get(), e.what()
                );
            pdp.erase(pdp.begin() + i);
        }
    }

    VectorOf(AuthnQueryDescriptorType) authnq=entity.getAuthnQueryDescriptorTypes();
    for (VectorOf(AuthnQueryDescriptorType)::size_type i=0; i<authnq.size(); ) {
        try {
            verifySignature(authnq[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out AuthnQueryDescriptorType for entity (%s) after failed signature check: %s", id.get(), e.what()
                );
            authnq.erase(authnq.begin() + i);
        }
    }

    VectorOf(AttributeQueryDescriptorType) attrq=entity.getAttributeQueryDescriptorTypes();
    for (VectorOf(AttributeQueryDescriptorType)::size_type i=0; i<attrq.size(); ) {
        try {
            verifySignature(attrq[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out AttributeQueryDescriptorType for entity (%s) after failed signature check: %s", id.get(), e.what()
                );
            attrq.erase(attrq.begin() + i);
        }
    }

    VectorOf(AuthzDecisionQueryDescriptorType) authzq=entity.getAuthzDecisionQueryDescriptorTypes();
    for (VectorOf(AuthzDecisionQueryDescriptorType)::size_type i=0; i<authzq.size(); ) {
        try {
            verifySignature(authzq[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out AuthzDecisionQueryDescriptorType for entity (%s) after failed signature check: %s", id.get(), e.what()
                );
            authzq.erase(authzq.begin() + i);
        }
    }

    VectorOf(RoleDescriptor) v=entity.getRoleDescriptors();
    for (VectorOf(RoleDescriptor)::size_type i=0; i<v.size(); ) {
        try {
            verifySignature(v[i]->getSignature(), entity.getEntityID());
            i++;
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn(
                "filtering out role (%s) for entity (%s) after failed signature check: %s",
                v[i]->getElementQName().toString().c_str(), id.get(), e.what()
                );
            v.erase(v.begin() + i);
        }
    }

    if (entity.getAffiliationDescriptor()) {
        try {
            verifySignature(entity.getAffiliationDescriptor()->getSignature(), entity.getEntityID());
        }
        catch (exception& e) {
            auto_ptr_char id(entity.getEntityID());
            m_log.warn("filtering out affiliation from entity (%s) after failed signature check: %s", id.get(), e.what());
            entity.setAffiliationDescriptor(nullptr);
        }
    }
}

void SignatureMetadataFilter::verifySignature(Signature* sig, const XMLCh* peerName) const
{
    if (!sig)
        return;

    m_profileValidator.validate(sig);

    // Set up criteria.
    CredentialCriteria cc;
    cc.setUsage(Credential::SIGNING_CREDENTIAL);
    cc.setSignature(*sig, CredentialCriteria::KEYINFO_EXTRACTION_KEY);

    if (m_credResolver) {
        if (peerName) {
            auto_ptr_char pname(peerName);
            cc.setPeerName(pname.get());
        }
        Locker locker(m_credResolver);
        vector<const Credential*> creds;
        if (m_credResolver->resolve(creds,&cc)) {
            SignatureValidator sigValidator;
            for (vector<const Credential*>::const_iterator i = creds.begin(); i != creds.end(); ++i) {
                try {
                    sigValidator.setCredential(*i);
                    sigValidator.validate(sig);
                    return; // success!
                }
                catch (exception&) {
                }
            }
            throw MetadataFilterException("Unable to verify signature with supplied key(s).");
        }
        else {
            throw MetadataFilterException("CredentialResolver did not supply any candidate keys.");
        }
    }
    else if (m_trust) {
        if (m_verifyName && peerName) {
            auto_ptr_char pname(peerName);
            cc.setPeerName(pname.get());
        }
        DummyCredentialResolver dummy;
        if (m_trust->validate(*sig, dummy, &cc))
            return;
        throw MetadataFilterException("TrustEngine unable to verify signature.");
    }

    throw MetadataFilterException("Unable to verify signature.");
}
