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

#include "internal.h"

#include <saml/SAMLConfig.h>
#include <saml/binding/MessageDecoder.h>
#include <saml/binding/MessageEncoder.h>
#include <saml/binding/SecurityPolicy.h>
#include <saml/binding/SecurityPolicyRule.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>

#include <boost/scoped_ptr.hpp>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/TrustEngine.h>
#include <xmltooling/util/URLEncoder.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;

class SAMLBindingBaseTestCase : public HTTPRequest, public HTTPResponse
{
protected:
    boost::scoped_ptr<CredentialResolver> m_creds;
    boost::scoped_ptr<MetadataProvider> m_metadata;
    boost::scoped_ptr<TrustEngine> m_trust;
    map<string,string> m_fields;
    map<string,string> m_headers;
    string m_method,m_url,m_query;
    vector<XSECCryptoX509*> m_clientCerts;
    vector<const SecurityPolicyRule*> m_rules;

public:
    void setUp() {
        m_fields.clear();
        m_headers.clear();
        m_method.erase();
        m_url.erase();
        m_query.erase();

        try {
            string config = data_path + "binding/ExampleMetadataProvider.xml";
            ifstream in(config.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
    
            auto_ptr_XMLCh path("path");
            string s = data_path + "binding/example-metadata.xml";
            auto_ptr_XMLCh file(s.c_str());
            doc->getDocumentElement()->setAttributeNS(nullptr,path.get(),file.get());
    
            m_metadata.reset(
                SAMLConfig::getConfig().MetadataProviderManager.newPlugin(XML_METADATA_PROVIDER, doc->getDocumentElement(), false)
                );
            m_metadata->init();

            config = data_path + "FilesystemCredentialResolver.xml";
            ifstream in2(config.c_str());
            DOMDocument* doc2=XMLToolingConfig::getConfig().getParser().parse(in2);
            XercesJanitor<DOMDocument> janitor2(doc2);
            m_creds.reset(
                XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER, doc2->getDocumentElement(), false)
                );
                
            m_trust.reset(XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(EXPLICIT_KEY_TRUSTENGINE, nullptr, false));

            m_rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(MESSAGEFLOW_POLICY_RULE,nullptr, false));
            m_rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(SIMPLESIGNING_POLICY_RULE,nullptr, false));
            m_rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(XMLSIGNING_POLICY_RULE,nullptr, false));
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            tearDown();
            throw;
        }

    }
    
    void tearDown() {
        for_each(m_rules.begin(), m_rules.end(), xmltooling::cleanup<SecurityPolicyRule>());
        m_trust.reset();
        m_metadata.reset();
        m_creds.reset();
        m_rules.clear();
        m_fields.clear();
        m_headers.clear();
        m_method.erase();
        m_url.erase();
        m_query.erase();
    }

    // HTTPRequest methods

    const char* getMethod() const {
        return m_method.c_str();
    }

    const char* getScheme() const {
        return "https";
    }

    const char* getHostname() const {
        return "localhost";
    }

    int getPort() const {
        return 443;
    }

    string getContentType() const {
        return "application/x-www-form-urlencoded";
    }

    long getContentLength() const {
        return -1;
    }

    const char* getRequestURI() const {
        return "/";
    }

    const char* getRequestURL() const {
        return m_url.c_str();
    }
    
    const char* getRequestBody() const {
        return nullptr;
    }
    
    const char* getQueryString() const {
        return m_query.c_str();
    }
    
    string getRemoteUser() const {
        return "";
    }

    string getRemoteAddr() const {
        return "127.0.0.1";
    }

    const std::vector<XSECCryptoX509*>& getClientCertificates() const {
        return m_clientCerts;
    }

    string getHeader(const char* name) const {
        map<string,string>::const_iterator i=m_headers.find(name);
        return i==m_headers.end() ? "" : i->second;
    }
    
    const char* getParameter(const char* name) const {
        map<string,string>::const_iterator i=m_fields.find(name);
        return i==m_fields.end() ? nullptr : i->second.c_str();
    }

    vector<const char*>::size_type getParameters(const char* name, vector<const char*>& values) const {
        values.clear();
        map<string,string>::const_iterator i=m_fields.find(name);
        if (i!=m_fields.end())
            values.push_back(i->second.c_str());
        return values.size();
    }
    
    // HTTPResponse methods
    
    void setResponseHeader(const char* name, const char* value, bool replace=false) {
        m_headers[name] = value ? value : "";
    }

    // The amount of error checking missing from this is incredible, but as long
    // as the test data isn't unexpected or malformed, it should work.
    
    long sendRedirect(const char* url) {
        m_method = "GET";
        char* dup = strdup(url);
        char* pch = strchr(dup,'?');
        if (pch) {
            *pch++=0;
            m_query = pch;
            char* name=pch;
            while (name && *name) {
                pch=strchr(pch,'=');
                *pch++=0;
                char* value=pch;
                pch=strchr(pch,'&');
                if (pch)
                    *pch++=0;
                XMLToolingConfig::getConfig().getURLEncoder()->decode(value);
                m_fields[name] = value;
                name = pch; 
            }
        }
        m_url = dup;
        free(dup);
        return m_fields.size();
    }
    
    string html_decode(const string& s) const {
        string decoded;
        const char* ch=s.c_str();
        while (*ch) {
            if (*ch=='&') {
                if (!strncmp(ch,"&lt;",4)) {
                    decoded+='<'; ch+=4;
                }
                else if (!strncmp(ch,"&gt;",4)) {
                    decoded+='>'; ch+=4;
                }
                else if (!strncmp(ch,"&quot;",6)) {
                    decoded+='"'; ch+=6;
                }
                else if (*++ch=='#') {
                    decoded+=(char)atoi(++ch);
                    ch=strchr(ch,';')+1;
                }
            }
            else {
                decoded+=*ch++;
            }
        }
        return decoded;
    }
    
    using HTTPResponse::sendResponse;

    long sendResponse(std::istream& inputStream, long status) {
        m_method="POST";
        string page,line;
        while (getline(inputStream,line))
            page += line + '\n';
            
        const char* pch=strstr(page.c_str(),"action=\"");
        pch+=strlen("action=\"");
        m_url = html_decode(page.substr(pch-page.c_str(),strchr(pch,'"')-pch));

        while ((pch = strstr(pch,"<input type=\"hidden\" name=\""))) {
            pch+=strlen("<input type=\"hidden\" name=\"");
            string name = page.substr(pch-page.c_str(),strchr(pch,'"')-pch);
            pch=strstr(pch,"value=\"");
            pch+=strlen("value=\"");
            m_fields[name] = html_decode(page.substr(pch-page.c_str(),strchr(pch,'"')-pch));
        }
        return m_fields.size();
    }
};
