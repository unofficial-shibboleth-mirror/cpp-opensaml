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
 * @file saml/security/ChainingMetadataProvider.h
 * 
 * MetadataProvider that uses multiple providers in sequence.
 */

#ifndef __saml_chainmeta_h__
#define __saml_chainmeta_h__

#include <saml/saml2/metadata/ObservableMetadataProvider.h>
#include <xmltooling/util/Threads.h>

namespace opensaml {
    namespace saml2md {
        
        /**
         * MetadataProvider that uses multiple providers in sequence.
         */
        class SAML_API ChainingMetadataProvider
            : public ObservableMetadataProvider, public ObservableMetadataProvider::Observer {
        public:
            /**
             * Constructor.
             * 
             * If a DOM is supplied, the following XML content is supported:
             * 
             * <ul>
             *  <li>&lt;MetadataProvider&gt; elements with a type attribute
             * </ul>
             * 
             * XML namespaces are ignored in the processing of this content.
             * 
             * @param e DOM to supply configuration for provider
             */
            ChainingMetadataProvider(const DOMElement* e=NULL);
            
            /**
             * Destructor will delete any embedded engines.
             */
            virtual ~ChainingMetadataProvider();
    
            /**
             * Adds a provider for future calls. The provider <strong>MUST</strong> be
             * initialized before adding it. 
             * 
             * @param newProvider provider to add
             */
            void addMetadataProvider(MetadataProvider* newProvider) {
                m_providers.push_back(newProvider);
            }
    
            /**
             * Removes a provider. The caller must delete the provider if necessary.
             * 
             * @param oldProvider provider to remove
             * @return  the old provider
             */
            MetadataProvider* removeMetadataProvider(MetadataProvider* oldProvider) {
                for (std::vector<MetadataProvider*>::iterator i=m_providers.begin(); i!=m_providers.end(); i++) {
                    if (oldProvider==(*i)) {
                        m_providers.erase(i);
                        return oldProvider;
                    }
                }
                return NULL;
            }

            xmltooling::Lockable* lock();
            void unlock();
            void init();
            const xmltooling::KeyResolver* getKeyResolver() const;
            const xmltooling::XMLObject* getMetadata() const;
            const EntitiesDescriptor* getEntitiesDescriptor(const char* name, bool requireValidMetadata=true) const;
            const EntityDescriptor* getEntityDescriptor(const char* id, bool requireValidMetadata=true) const;
            const EntityDescriptor* getEntityDescriptor(const SAMLArtifact* artifact) const;
            void onEvent(MetadataProvider& provider);
    
        private:
            xmltooling::ThreadKey* m_tlsKey;
            std::vector<MetadataProvider*> m_providers;
        };
    };    
};

#endif /* __saml_chainmeta_h__ */
