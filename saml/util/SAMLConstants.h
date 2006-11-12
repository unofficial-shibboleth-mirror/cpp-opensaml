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
 * @file saml/util/SAMLConstants.h
 * 
 * SAML XML namespace constants 
 */

#ifndef __saml_xmlconstants_h__
#define __saml_xmlconstants_h__

#include <xmltooling/util/XMLConstants.h>

/**
 * SAML related constants.
 */
namespace samlconstants {
    
    /**  Liberty PAOS XML Namespace ("urn:liberty:paos:2003-08") */
    extern SAML_API const XMLCh PAOS_NS[];
    
    /**  Liberty PAOS QName prefix ("paos") */
    extern SAML_API const XMLCh PAOS_PREFIX[];

    /**  SAML 1.X Assertion XML namespace ("urn:oasis:names:tc:SAML:1.0:assertion") */
    extern SAML_API const XMLCh SAML1_NS[];

    /**  SAML 1.X Protocol XML namespace ("urn:oasis:names:tc:SAML:1.0:protocol") */
    extern SAML_API const XMLCh SAML1P_NS[];
    
    /** SAML 1.X Assertion QName prefix ("saml") */
    extern SAML_API const XMLCh SAML1_PREFIX[];

    /** SAML 1.X Protocol QName prefix ("samlp") */
    extern SAML_API const XMLCh SAML1P_PREFIX[];
    
    /**  SAML 2.0 Version ("2.0") */
    extern SAML_API const XMLCh SAML20_VERSION[];
    
    /**  SAML 2.0 Assertion XML namespace ("urn:oasis:names:tc:SAML:2.0:assertion") */
    extern SAML_API const XMLCh SAML20_NS[];

    /**  SAML 2.0 Protocol XML namespace ("urn:oasis:names:tc:SAML:2.0:protocol") */
    extern SAML_API const XMLCh SAML20P_NS[];

    /**  SAML 2.0 Metadata XML namespace ("urn:oasis:names:tc:SAML:2.0:metadata") */
    extern SAML_API const XMLCh SAML20MD_NS[];

    /**  SAML 2.0 AuthnContext XML namespace ("urn:oasis:names:tc:SAML:2.0:ac") */
    extern SAML_API const XMLCh SAML20AC_NS[];
    
    /** SAML 2.0 Assertion QName prefix ("saml") */
    extern SAML_API const XMLCh SAML20_PREFIX[];

    /** SAML 2.0 Protocol QName prefix ("samlp") */
    extern SAML_API const XMLCh SAML20P_PREFIX[];

    /** SAML 2.0 Metadata QName prefix ("md") */
    extern SAML_API const XMLCh SAML20MD_PREFIX[];

    /** SAML 2.0 AuthnContext QName prefix ("ac") */
    extern SAML_API const XMLCh SAML20AC_PREFIX[];

    /** SAML 2.0 Enhanced Client/Proxy SSO Profile XML Namespace ("urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp") */
    extern SAML_API const XMLCh SAML20ECP_NS[];
    
    /** SAML 2.0 Enhanced Client/Proxy SSO Profile QName prefix ("ecp") */
    extern SAML_API const XMLCh SAML20ECP_PREFIX[];

    /** SAML 2.0 DCE PAC Attribute Profile XML Namespace ("urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE") */
    extern SAML_API const XMLCh SAML20DCE_NS[];
    
    /** SAML 2.0 DCE PAC Attribute Profile QName prefix ("DCE") */
    extern SAML_API const XMLCh SAML20DCE_PREFIX[];

    /** SAML 2.0 X.500 Attribute Profile XML Namespace ("urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500") */
    extern SAML_API const XMLCh SAML20X500_NS[];
    
    /** SAML 2.0 X.500 Attribute Profile QName prefix ("x500") */
    extern SAML_API const XMLCh SAML20X500_PREFIX[];

    /** SAML 2.0 XACML Attribute Profile XML Namespace ("urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML") */
    extern SAML_API const XMLCh SAML20XACML_NS[];
    
    /** SAML 2.0 XACML Attribute Profile QName prefix ("xacmlprof") */
    extern SAML_API const XMLCh SAML20XACML_PREFIX[];

    /** SAML 1.x Metadata Profile XML Namespace ("urn:oasis:names:tc:SAML:profiles:v1metadata") */
    extern SAML_API const XMLCh SAML1MD_NS[];
    
    /** SAML 1.x Metadata Profile QName prefix ("saml1md") */
    extern SAML_API const XMLCh SAML1MD_PREFIX[];

    /** SAML 1.0 Protocol Enumeration constant ("urn:oasis:names:tc:SAML:1.0:protocol") */
    #define SAML10_PROTOCOL_ENUM SAML1P_NS
    
    /** SAML 1.1 Protocol Enumeration constant ("urn:oasis:names:tc:SAML:1.1:protocol") */
    extern SAML_API const XMLCh SAML11_PROTOCOL_ENUM[];

    /** SAML Query Requester Metadata Extension XML Namespace ("urn:oasis:names:tc:SAML:metadata:ext:query") */
    extern SAML_API const XMLCh SAML20MD_QUERY_EXT_NS[];
    
    /** SAML Query Requester Metadata Extension QName prefix ("query") */
    extern SAML_API const XMLCh SAML20MD_QUERY_EXT_PREFIX[];

    /** SAML Third-Party Request Protocol Extension XML Namespace ("urn:oasis:names:tc:SAML:protocol:ext:third-party") */
    extern SAML_API const XMLCh SAML20P_THIRDPARTY_EXT_NS[];
    
    /** SAML Third-Party Request Protocol Extension QName prefix ("query") */
    extern SAML_API const XMLCh SAML20P_THIRDPARTY_EXT_PREFIX[];

    /** SAML 1.x SOAP binding ("urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding") */
    extern SAML_API const char SAML1_BINDING_SOAP[];

    /** SAML 1.x Browser Artifact profile ("urn:oasis:names:tc:SAML:1.0:profiles:artifact-01") */
    extern SAML_API const char SAML1_PROFILE_BROWSER_ARTIFACT[];

    /** SAML 1.x Browser POST profile ("urn:oasis:names:tc:SAML:1.0:profiles:browser-post") */
    extern SAML_API const char SAML1_PROFILE_BROWSER_POST[];
    
    /** SAML 2.0 SOAP binding ("urn:oasis:names:tc:SAML:2.0:bindings:SOAP") */
    extern SAML_API const char SAML20_BINDING_SOAP[];

    /** SAML 2.0 HTTP-Artifact binding ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact") */
    extern SAML_API const char SAML20_BINDING_HTTP_ARTIFACT[];

    /** SAML 2.0 HTTP-POST binding ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") */
    extern SAML_API const char SAML20_BINDING_HTTP_POST[];
    
    /** SAML 2.0 HTTP-POST-SimpleSign binding ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign") */
    extern SAML_API const char SAML20_BINDING_HTTP_POST_SIMPLESIGN[];

    /** SAML 2.0 HTTP-Redirect binding ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect") */
    extern SAML_API const char SAML20_BINDING_HTTP_REDIRECT[];
    
    /** SAML 2.0 HTTP-Redirect DEFLATE URL encoding ("urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE") */
    extern SAML_API const char SAML20_BINDING_URL_ENCODING_DEFLATE[];
};

#endif /* __saml_xmlconstants_h__ */
