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
 * @file saml/saml2/core/SAML2ArtifactType0004.h
 * 
 * Type 0x0004 SAML 2.0 artifact class
 */

#ifndef __saml_artifacttype0004_h__
#define __saml_artifacttype0004_h__

#include <saml/saml2/binding/SAML2Artifact.h>

namespace opensaml {
    namespace saml2p {
        
        /**
         * Type 0x0004 SAML 2.0 artifact class
         */
        class SAML_API SAML2ArtifactType0004 : public SAML2Artifact
        {
            SAML2ArtifactType0004& operator=(const SAML2ArtifactType0004& src);
        public:
            /**
             * Decodes a base64-encoded type 0x0004 artifact
             * 
             * @param s NULL-terminated base64-encoded string 
             */        
            SAML2ArtifactType0004(const char* s);

            /**
             * Constructs an artifact with the specified source ID and index, but a random message handle.
             * 
             * @param sourceid  SOURCEID_LENGTH bytes of binary data
             * @param index     endpoint index
             */        
            SAML2ArtifactType0004(const std::string& sourceid, int index);

            /**
             * Constructs an artifact with the specified source ID and assertion handle.
             * 
             * @param sourceid  SOURCEID_LENGTH bytes of binary data
             * @param index     endpoint index
             * @param handle    HANDLE_LENGTH bytes of binary data 
             */        
            SAML2ArtifactType0004(const std::string& sourceid, int index, const std::string& handle);
    
            virtual ~SAML2ArtifactType0004() {}
            
            virtual SAML2ArtifactType0004* clone() const {
                return new SAML2ArtifactType0004(*this);
            }
            
            virtual std::string getSource() const {
                return toHex(getSourceID());
            }

            /**
             * Returns the binary data that identifies the source.
             * The result MAY contain embedded null characters.
             * 
             * @return the binary source ID
             */
            virtual std::string getSourceID() const {
                return m_raw.substr(TYPECODE_LENGTH + INDEX_LENGTH, SOURCEID_LENGTH);    // bytes 5-24
            }
            
            virtual std::string getMessageHandle() const {
                return m_raw.substr(TYPECODE_LENGTH + INDEX_LENGTH + SOURCEID_LENGTH, HANDLE_LENGTH);    // bytes 25-44
            }

            /** Length of source ID */            
            static const unsigned int SOURCEID_LENGTH;

            /** Length of message handle */            
            static const unsigned int HANDLE_LENGTH;
    
        protected:
            SAML2ArtifactType0004(const SAML2ArtifactType0004& src) : SAML2Artifact(src) {}
        };
        
    };
};

#endif /* __saml_artifacttype0004_h__ */
