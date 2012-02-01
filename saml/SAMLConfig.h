/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * @file saml/SAMLConfig.h
 * 
 * Library configuration.
 */

#ifndef __saml_config_h__
#define __saml_config_h__

#include <saml/base.h>

#include <string>
#include <xercesc/dom/DOM.hpp>
#include <xmltooling/PluginManager.h>

/**
 * @namespace opensaml
 * Common classes for OpenSAML library
 */
namespace opensaml {

    class SAML_API ArtifactMap;
    class SAML_API MessageEncoder;
    class SAML_API MessageDecoder;
    class SAML_API SAMLArtifact;
    class SAML_API SecurityPolicyRule;

    namespace saml2md {
        class SAML_API ContactPerson;
        class SAML_API EntityDescriptor;
        class SAML_API MetadataProvider;
        class SAML_API MetadataFilter;
        class SAML_API RoleDescriptor;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    /**
     * Singleton object that manages library startup/shutdown.configuration.
     */
    class SAML_API SAMLConfig
    {
    MAKE_NONCOPYABLE(SAMLConfig);
    public:
        virtual ~SAMLConfig();

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
         * before using any library classes. The flag controls whether this is the
         * "dominant" library or not and can allow the SAML library to be loaded
         * as an extension of XMLTooling rather than subsuming it.
         * 
         * @param initXMLTooling true iff this method should initialize the XMLTooling layer
         * @return true iff initialization was successful 
         */
        virtual bool init(bool initXMLTooling=true)=0;
        
        /**
         * Shuts down library
         * 
         * Each process using the library SHOULD call this function exactly once
         * before terminating itself. The flag controls whether this is the
         * "dominant" library or not and can allow the SAML library to be loaded
         * as an extension of XMLTooling rather than subsuming it.
         * 
         * @param termXMLTooling true iff this method should shutdown the XMLTooling layer
         */
        virtual void term(bool termXMLTooling=true)=0;
        
        /**
         * Sets the global ArtifactMap instance.
         * This method must be externally synchronized with any code that uses the object.
         * Any previously set object is destroyed.
         * 
         * @param artifactMap   new ArtifactMap instance to store
         */
        void setArtifactMap(ArtifactMap* artifactMap);
        
        /**
         * Returns the global ArtifactMap instance.
         * 
         * @return  global ArtifactMap or nullptr
         */
        ArtifactMap* getArtifactMap() const;

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
         * @deprecated
         * Generate the SHA-1 hash of a string
         * 
         * @param s     NULL-terminated string to hash
         * @param toHex true iff the result should be encoded in hexadecimal form or left as raw bytes
         *  
         * @return  SHA-1 hash of the data
         */
        virtual std::string hashSHA1(const char* s, bool toHex=false)=0;

        /**
         * Sets the order of contact types to use in annotating exceptions with contact information.
         *
         * @param contactTypes  whitespace-delimited list of contact types
         */
        virtual void setContactPriority(const XMLCh* contactTypes)=0;

        /**
         * Returns the appropriate contact to use for the entity.
         *
         * @param entity    the entity to search
         * @return  a contact to use, or nullptr
         */
        virtual const saml2md::ContactPerson* getContactPerson(const saml2md::EntityDescriptor& entity) const=0;

        /**
         * Returns the appropriate contact to use for the role.
         *
         * @param entity    the role to search
         * @return  a contact to use, or nullptr
         */
        virtual const saml2md::ContactPerson* getContactPerson(const saml2md::RoleDescriptor& role) const=0;

        /** Manages factories for MessageDecoder plugins. */
        xmltooling::PluginManager< MessageDecoder,std::string,std::pair<const xercesc::DOMElement*,const XMLCh*> > MessageDecoderManager;

        /** Manages factories for MessageEncoder plugins. */
        xmltooling::PluginManager< MessageEncoder,std::string,std::pair<const xercesc::DOMElement*,const XMLCh*> > MessageEncoderManager;

        /** Manages factories for SAMLArtifact plugins. */
        xmltooling::PluginManager<SAMLArtifact,std::string,const char*> SAMLArtifactManager;

        /** Manages factories for SecurityPolicyRule plugins. */
        xmltooling::PluginManager<SecurityPolicyRule,std::string,const xercesc::DOMElement*> SecurityPolicyRuleManager;

        /** Manages factories for MetadataProvider plugins. */
        xmltooling::PluginManager<saml2md::MetadataProvider,std::string,const xercesc::DOMElement*> MetadataProviderManager;
        
        /** Manages factories for MetadataFilter plugins. */
        xmltooling::PluginManager<saml2md::MetadataFilter,std::string,const xercesc::DOMElement*> MetadataFilterManager;

    protected:
        SAMLConfig();
        
        /** Global ArtifactMap instance for use by artifact-related functions. */
        ArtifactMap* m_artifactMap;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
    
};

#endif /* __saml_config_h__ */
