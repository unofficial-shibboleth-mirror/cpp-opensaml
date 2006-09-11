/*
 *  Copyright 2001-2005 Internet2
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

#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
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

static const XMLCh GenericMetadataProvider[] =      UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
static const XMLCh type[] =                         UNICODE_LITERAL_4(t,y,p,e);

ChainingMetadataProvider::ChainingMetadataProvider(const DOMElement* e) : ObservableMetadataProvider(e), m_tlsKey(NULL)
{
    try {
        e = e ? xmltooling::XMLHelper::getFirstChildElement(e, GenericMetadataProvider) : NULL;
        while (e) {
            auto_ptr_char temp(e->getAttributeNS(NULL,type));
            if (temp.get()) {
                auto_ptr<MetadataProvider> provider(
                    SAMLConfig::getConfig().MetadataProviderManager.newPlugin(temp.get(), e)
                    );
                ObservableMetadataProvider* obs = dynamic_cast<ObservableMetadataProvider*>(provider.get());
                if (obs)
                    obs->addObserver(this);
                m_providers.push_back(provider.get());
                provider.release();
            }
            e = XMLHelper::getNextSiblingElement(e, GenericMetadataProvider);
        }
    }
    catch (XMLToolingException&) {
        for_each(m_providers.begin(), m_providers.end(), xmltooling::cleanup<MetadataProvider>());
        throw;
    }
    m_tlsKey = ThreadKey::create(NULL);
}

ChainingMetadataProvider::~ChainingMetadataProvider()
{
    delete m_tlsKey;
    for_each(m_providers.begin(), m_providers.end(), xmltooling::cleanup<MetadataProvider>());
}

void ChainingMetadataProvider::onEvent(MetadataProvider& provider)
{
    emitChangeEvent();
}

void ChainingMetadataProvider::init()
{
    for_each(m_providers.begin(), m_providers.end(), mem_fun<void,MetadataProvider>(&MetadataProvider::init));
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

const KeyResolver* ChainingMetadataProvider::getKeyResolver() const
{
    // Check for a locked provider.
    void* ptr=m_tlsKey->getData();
    return ptr ? reinterpret_cast<MetadataProvider*>(ptr)->getKeyResolver() : NULL;
    
}

const XMLObject* ChainingMetadataProvider::getMetadata() const
{
    throw XMLToolingException("getMetadata operation not implemented on this provider.");
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
