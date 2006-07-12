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
 * @file saml/SAMLConfig.h
 * 
 * Library configuration 
 */

#ifndef __saml_config_h__
#define __saml_config_h__

#include <saml/base.h>
#include <saml/saml2/metadata/MetadataProvider.h>

#include <xmltooling/PluginManager.h>
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>

#include <string>

/**
 * @namespace opensaml
 * Common classes for OpenSAML library
 */
namespace opensaml {

    /**
     * Singleton object that manages library startup/shutdown.configuration.
     */
    class SAML_API SAMLConfig
    {
    MAKE_NONCOPYABLE(SAMLConfig);
    public:
        virtual ~SAMLConfig() {}

        /**
         * Returns the global configuration object for the library.
         * 
         * @return reference to the global library configuration object
         */
        static SAMLConfig& getConfig();
        
        /**
         * Initializes library
         * 
         * Each process using the library MUST call this function exactly once
         * before using any library classes.
         * 
         * @return true iff initialization was successful 
         */
        virtual bool init()=0;
        
        /**
         * Shuts down library
         * 
         * Each process using the library SHOULD call this function exactly once
         * before terminating itself
         */
        virtual void term()=0;
        
        /**
         * Generate random information using the underlying security library
         * 
         * @param buf   buffer for the information
         * @param len   number of bytes to write into buffer
         */
        virtual void generateRandomBytes(void* buf, unsigned int len)=0;

        /**
         * Generate random information using the underlying security library
         * 
         * @param buf   string buffer for the information
         * @param len   number of bytes to write into buffer
         */
        virtual void generateRandomBytes(std::string& buf, unsigned int len)=0;

        /**
         * Generate a valid XML identifier of the form _X{32} where X is a
         * random hex character. The caller is responsible for freeing the result.
         * 
         * @return a valid null-terminated XML ID
         */
        virtual XMLCh* generateIdentifier()=0;
        
        /**
         * Manages factories for MetadataProvider plugins.
         */
        xmltooling::PluginManager<saml2md::MetadataProvider,const DOMElement*> MetadataProviderManager;
        
        /**
         * Manages factories for MetadataFilter plugins.
         */
        xmltooling::PluginManager<saml2md::MetadataFilter,const DOMElement*> MetadataFilterManager;

    protected:
        SAMLConfig() {}
    };

};

#endif /* __saml_config_h__ */
