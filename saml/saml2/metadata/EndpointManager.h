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
 * @file saml/saml2/metadata/EndpointManager.h
 * 
 * Templates for processing endpoint information.
 */

#ifndef __saml_epmgr_h__
#define __saml_epmgr_h__

#include <saml/base.h>

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
            typename const std::vector<_Tx*>& m_endpoints;
            
        public:
            /**
             * Constructor.
             *
             * @param endpoints array of endpoints to manage
             */
            EndpointManager(typename const std::vector<_Tx*>& endpoints) : m_endpoints(endpoints) {
            }
            
            /**
             * Returns endpoint that supports a particular binding.
             * 
             * @param binding   binding to locate
             * @return a supporting endpoint, favoring the default, or NULL
             */
            const _Tx* getByBinding(const XMLCh* binding) const {
                for (std::vector<_Tx*>::const_iterator i = m_endpoints.begin(); i!=m_endpoints.end(); ++i) {
                    if (xercesc::XMLString::equals(binding,(*i)->getBinding()))
                        return *i;
                }
                return NULL;
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
            typename const _Tx* m_default;
            
        public:
            /**
             * Constructor.
             *
             * @param endpoints array of endpoints to manage
             */
            IndexedEndpointManager(typename const std::vector<_Tx*>& endpoints) : EndpointManager(endpoints), m_default(NULL) {
            }
            
            /**
             * Returns the default endpoint in the set.
             * 
             * @return the default endpoint 
             */
            const _Tx* getDefault() const {
                if (m_default)
                    return m_default;
                for (std::vector<_Tx*>::const_iterator i = m_endpoints.begin(); i!=m_endpoints.end(); ++i) {
                    if ((*i)->isDefault())
                        return m_default=*i;
                }
                return (m_endpoints.empty()) ? m_default=NULL : m_default=m_endpoints.front();
            }
            
            /**
             * Returns indexed endpoint.
             * 
             * @param index index to locate
             * @return matching endpoint, or NULL
             */
            const _Tx* getByIndex(unsigned short index) const {
                for (std::vector<_Tx*>::const_iterator i = m_endpoints.begin(); i!=m_endpoints.end(); ++i) {
                    std::pair<bool,int> comp = (*i)->getIndex();
                    if (comp.first && index == comp.second)
                        return *i;
                }
                return NULL;
            }
            
            /**
             * Returns endpoint that supports a particular binding.
             * 
             * @param binding   binding to locate
             * @return a supporting endpoint, favoring the default, or NULL
             */
            const _Tx* getByBinding(const XMLCh* binding) const {
                if (getDefault() && xercesc::XMLString::equals(binding,m_default->getBinding()))
                    return m_default;
                return EndpointManager::getByBinding(binding);
            }
        };
    };
};

#endif /* __saml_epmgr_h__ */
