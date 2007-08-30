/*
 *  Copyright 2001-2007 Internet2
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
 * ChainingMetadataProvider.cpp
 * 
 * MetadataProvider that uses multiple providers in sequence.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/metadata/ChainingMetadataProvider.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/util/XMLHelper.h>


using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {
        MetadataProvider* SAML_DLLLOCAL ChainingMetadataProviderFactory(const DOMElement* const & e)
        {
            return new ChainingMetadataProvider(e);
        }
    };
};

static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
static const XMLCh type[] =                 UNICODE_LITERAL_4(t,y,p,e);

ChainingMetadataProvider::ChainingMetadataProvider(const DOMElement* e) : ObservableMetadataProvider(e), m_tlsKey(NULL)
{
    Category& log=Category::getInstance(SAML_LOGCAT".Metadata.Chaining");
    e = e ? XMLHelper::getFirstChildElement(e, _MetadataProvider) : NULL;
    while (e) {
        auto_ptr_char temp(e->getAttributeNS(NULL,type));
        if (temp.get() && *temp.get()) {
            try {
                log.info("building MetadataProvider of type %s", temp.get());
                auto_ptr<MetadataProvider> provider(
                    SAMLConfig::getConfig().MetadataProviderManager.newPlugin(temp.get(), e)
                    );
                ObservableMetadataProvider* obs = dynamic_cast<ObservableMetadataProvider*>(provider.get());
                if (obs)
                    obs->addObserver(this);
                m_providers.push_back(provider.get());
                provider.release();
            }
            catch (exception& ex) {
                log.error("error building MetadataProvider: %s", ex.what());
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _MetadataProvider);
    }
    m_tlsKey = ThreadKey::create(NULL);
}

ChainingMetadataProvider::~ChainingMetadataProvider()
{
    delete m_tlsKey;
    for_each(m_providers.begin(), m_providers.end(), xmltooling::cleanup<MetadataProvider>());
}

void ChainingMetadataProvider::onEvent(const ObservableMetadataProvider& provider) const
{
    emitChangeEvent();
}

void ChainingMetadataProvider::init()
{
    for (vector<MetadataProvider*>::const_iterator i=m_providers.begin(); i!=m_providers.end(); ++i) {
        try {
            (*i)->init();
        }
        catch (exception& ex) {
            Category::getInstance(SAML_LOGCAT".Metadata").error("failure initializing MetadataProvider: %s", ex.what());
        }
    }
}

Lockable* ChainingMetadataProvider::lock()
{
    return this;   // we're not lockable ourselves...
}

void ChainingMetadataProvider::unlock()
{
    // Check for a locked provider.
    void* ptr=m_tlsKey->getData();
    if (ptr) {
        m_tlsKey->setData(NULL);
        reinterpret_cast<MetadataProvider*>(ptr)->unlock();
    }
}

const XMLObject* ChainingMetadataProvider::getMetadata() const
{
    throw MetadataException("getMetadata operation not implemented on this provider.");
}

const EntitiesDescriptor* ChainingMetadataProvider::getEntitiesDescriptor(const char* name, bool requireValidMetadata) const
{
    // Clear any existing lock.
    const_cast<ChainingMetadataProvider*>(this)->unlock();

    // Do a search.
    const EntitiesDescriptor* ret=NULL;
    for (vector<MetadataProvider*>::const_iterator i=m_providers.begin(); i!=m_providers.end(); ++i) {
        (*i)->lock();
        if (ret=(*i)->getEntitiesDescriptor(name,requireValidMetadata)) {
            // Save locked provider.
            m_tlsKey->setData(*i);
            return ret;
        }
        (*i)->unlock();
    }

    return NULL;
}

const EntityDescriptor* ChainingMetadataProvider::getEntityDescriptor(const char* id, bool requireValidMetadata) const
{
    // Clear any existing lock.
    const_cast<ChainingMetadataProvider*>(this)->unlock();

    // Do a search.
    const EntityDescriptor* ret=NULL;
    for (vector<MetadataProvider*>::const_iterator i=m_providers.begin(); i!=m_providers.end(); ++i) {
        (*i)->lock();
        if (ret=(*i)->getEntityDescriptor(id,requireValidMetadata)) {
            // Save locked provider.
            m_tlsKey->setData(*i);
            return ret;
        }
        (*i)->unlock();
    }

    return NULL;
}

const EntityDescriptor* ChainingMetadataProvider::getEntityDescriptor(const SAMLArtifact* artifact) const
{
    // Clear any existing lock.
    const_cast<ChainingMetadataProvider*>(this)->unlock();

    // Do a search.
    const EntityDescriptor* ret=NULL;
    for (vector<MetadataProvider*>::const_iterator i=m_providers.begin(); i!=m_providers.end(); ++i) {
        (*i)->lock();
        if (ret=(*i)->getEntityDescriptor(artifact)) {
            // Save locked provider.
            m_tlsKey->setData(*i);
            return ret;
        }
        (*i)->unlock();
    }

    return NULL;
}

const Credential* ChainingMetadataProvider::resolve(const CredentialCriteria* criteria) const
{
    // Check for a locked provider.
    void* ptr=m_tlsKey->getData();
    if (!ptr)
        throw MetadataException("No locked MetadataProvider, where did the role object come from?");

    return reinterpret_cast<MetadataProvider*>(ptr)->resolve(criteria);
}

vector<const Credential*>::size_type ChainingMetadataProvider::resolve(
    vector<const Credential*>& results, const CredentialCriteria* criteria
    ) const
{
    // Check for a locked provider.
    void* ptr=m_tlsKey->getData();
    if (!ptr)
        throw MetadataException("No locked MetadataProvider, where did the role object come from?");

    return reinterpret_cast<MetadataProvider*>(ptr)->resolve(results, criteria);
}
