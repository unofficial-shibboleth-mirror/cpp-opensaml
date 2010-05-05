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
 * @file saml/saml2/metadata/ObservableMetadataProvider.h
 * 
 * A metadata provider that notifies interested parties of changes.
 */

#ifndef __saml2_obsmetadataprov_h__
#define __saml2_obsmetadataprov_h__

#include <saml/saml2/metadata/MetadataProvider.h>

namespace xmltooling {
    class XMLTOOL_API Mutex;
};

namespace opensaml {
    
    namespace saml2md {
        
#if defined (_MSC_VER)
        #pragma warning( push )
        #pragma warning( disable : 4251 )
#endif
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
            ObservableMetadataProvider(const xercesc::DOMElement* e=nullptr);
            
            /**
             * Convenience method for notifying every registered Observer of an event.
             */
            virtual void emitChangeEvent() const;

        public:
            virtual ~ObservableMetadataProvider();
            
            /**
             * An observer of metadata provider changes.
             */
            class SAML_API Observer {
                MAKE_NONCOPYABLE(Observer);
            protected:
                Observer();
            public:
                virtual ~Observer();
        
                /**
                 * Called when a provider signals an event has occured.
                 * The provider is already locked. 
                 * 
                 * @param provider the provider being observed
                 */
                virtual void onEvent(const ObservableMetadataProvider& provider) const=0;
            };
            
            /**
             * Adds a metadata observer.
             * 
             * @param newObserver metadata observer to add
             */
            virtual void addObserver(const Observer* newObserver) const;

            /**
             * Removes a metadata observer.
             * 
             * @param oldObserver metadata observer to remove
             * @return  the old observer
             */
            virtual const Observer* removeObserver(const Observer* oldObserver) const;

        private:
            mutable xmltooling::Mutex* m_observerLock;
            mutable std::vector<const Observer*> m_observers;
        };

#if defined (_MSC_VER)
        #pragma warning( pop )
#endif

    };
};

#endif /* __saml2_obsmetadataprov_h__ */
