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
 * @file saml/saml2/metadata/ObservableMetadataProvider.h
 * 
 * A metadata provider that notifies interested parties of changes.
 */

#ifndef __saml2_obsmetadataprov_h__
#define __saml2_obsmetadataprov_h__

#include <saml/saml2/metadata/MetadataProvider.h>

namespace opensaml {
    
    namespace saml2md {
        
        /**
         * A metadata provider that notifies interested parties of changes.
         */
        class SAML_API ObservableMetadataProvider : public MetadataProvider
        {
        protected:
            /**
             * Constructor.
             * 
             * @param e DOM to supply configuration for provider
             */
            ObservableMetadataProvider(const DOMElement* e=NULL) : MetadataProvider(e) {}
            
            /**
             * Convenience method for notifying every registered Observer of an event.
             */
            virtual void emitChangeEvent();

        public:
            /**
             * Destructor will delete any installed filters.
             */
            virtual ~ObservableMetadataProvider();
            
            /**
             * An observer of metadata provider changes.
             */
            class SAML_API Observer {
                MAKE_NONCOPYABLE(Observer);
            protected:
                Observer() {}
            public:
                virtual ~Observer() {}
        
                /**
                 * Called when a provider signals an event has occured.
                 * The provider is already locked. 
                 * 
                 * @param provider the provider being observed
                 */
                virtual void onEvent(MetadataProvider& provider)=0;
            };
            
            /**
             * Adds a metadata observer.
             * 
             * @param newObserver metadata observer to add
             */
            virtual void addObserver(Observer* newObserver) {
                m_observers.push_back(newObserver);
            }

            /**
             * Removes a metadata observer. The caller must delete the observer if necessary.
             * 
             * @param oldObserver metadata observer to remove
             * @return  the old observer
             */
            virtual Observer* removeObserver(Observer* oldObserver) {
                for (std::vector<Observer*>::iterator i=m_observers.begin(); i!=m_observers.end(); i++) {
                    if (oldObserver==(*i)) {
                        m_observers.erase(i);
                        return oldObserver;
                    }
                }
                return NULL;
            }

        private:
            std::vector<Observer*> m_observers;
        };
    };
};

#endif /* __saml2_obsmetadataprov_h__ */
