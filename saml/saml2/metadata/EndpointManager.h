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
 * @file saml/saml2/metadata/EndpointManager.h
 * 
 * Templates for processing endpoint information.
 */

#ifndef __saml_epmgr_h__
#define __saml_epmgr_h__

#include <saml/base.h>

#include <vector>
#include <xercesc/util/XMLString.hpp>

namespace opensaml {
    namespace saml2md {
        
        /**
         * Template for processing unindexed endpoint information.
         * 
         * @param _Tx   the endpoint type being managed
         */
        template <class _Tx>
        class EndpointManager
        {
        protected:
            /** Reference to endpoint array. */
            const typename std::vector<_Tx*>& m_endpoints;
            
        public:
            /**
             * Constructor.
             *
             * @param endpoints array of endpoints to manage
             */
            EndpointManager(const typename std::vector<_Tx*>& endpoints) : m_endpoints(endpoints) {
            }
            
            /**
             * Returns endpoint that supports a particular binding.
             * 
             * @param binding   binding to locate
             * @return a supporting endpoint, favoring the default, or nullptr
             */
            const _Tx* getByBinding(const XMLCh* binding) const {
                for (typename std::vector<_Tx*>::const_iterator i = m_endpoints.begin(); i!=m_endpoints.end(); ++i) {
                    if (xercesc::XMLString::equals(binding,(*i)->getBinding()))
                        return *i;
                }
                return nullptr;
            }
        };

        /**
         * Template for processing indexed endpoint information.
         * 
         * @param _Tx   the endpoint type being managed
         */
        template <class _Tx>
        class IndexedEndpointManager : public EndpointManager<_Tx>
        {
            const _Tx* m_default;
            
        public:
            /**
             * Constructor.
             *
             * @param endpoints array of endpoints to manage
             */
            IndexedEndpointManager(const typename std::vector<_Tx*>& endpoints) : EndpointManager<_Tx>(endpoints), m_default(nullptr) {
            }
            
            /**
             * Returns the default endpoint in the set.
             * 
             * @return the default endpoint 
             */
            const _Tx* getDefault() const {
                if (m_default)
                    return m_default;
                for (typename std::vector<_Tx*>::const_iterator i = EndpointManager<_Tx>::m_endpoints.begin(); i!=EndpointManager<_Tx>::m_endpoints.end(); ++i) {
                    if ((*i)->isDefault())
                        return m_default=*i;
                }
                return (EndpointManager<_Tx>::m_endpoints.empty()) ? m_default=nullptr : m_default=EndpointManager<_Tx>::m_endpoints.front();
            }
            
            /**
             * Returns indexed endpoint.
             * 
             * @param index index to locate
             * @return matching endpoint, or nullptr
             */
            const _Tx* getByIndex(unsigned short index) const {
                for (typename std::vector<_Tx*>::const_iterator i = EndpointManager<_Tx>::m_endpoints.begin(); i!=EndpointManager<_Tx>::m_endpoints.end(); ++i) {
                    std::pair<bool,int> comp = (*i)->getIndex();
                    if (comp.first && index == comp.second)
                        return *i;
                }
                return nullptr;
            }
            
            /**
             * Returns endpoint that supports a particular binding.
             * 
             * @param binding   binding to locate
             * @return a supporting endpoint, favoring the default, or nullptr
             */
            const _Tx* getByBinding(const XMLCh* binding) const {
                if (getDefault() && xercesc::XMLString::equals(binding,m_default->getBinding()))
                    return m_default;
                return EndpointManager<_Tx>::getByBinding(binding);
            }
        };
    };
};

#endif /* __saml_epmgr_h__ */
