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

#include "internal.h"

#include <saml/SAMLConfig.h>
#include <saml/binding/MessageDecoder.h>
#include <saml/binding/MessageEncoder.h>
#include <saml/binding/URLEncoder.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/security/X509TrustEngine.h>

using namespace saml2md;
using namespace xmlsignature;

class SAMLBindingBaseTestCase : public MessageDecoder::HTTPRequest, public MessageEncoder::HTTPResponse
{
protected:
    CredentialResolver* m_creds; 
    MetadataProvider* m_metadata;
    opensaml::X509TrustEngine* m_trust;
    map<string,string> m_fields;
    map<string,string> m_headers;
    string m_method,m_url;

public:
    void setUp() {
        m_creds=NULL;
        m_metadata=NULL;
        m_trust=NULL;
        m_fields.clear();
        m_headers.clear();
        m_method.erase();
        m_url.erase();

        try {
            string config = data_path + "binding/ExampleMetadataProvider.xml";
            ifstream in(config.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
    
            auto_ptr_XMLCh path("path");
            string s = data_path + "binding/example-metadata.xml";
            auto_ptr_XMLCh file(s.c_str());
            doc->getDocumentElement()->setAttributeNS(NULL,path.get(),file.get());
    
            m_metadata = SAMLConfig::getConfig().MetadataProviderManager.newPlugin(
                FILESYSTEM_METADATA_PROVIDER,doc->getDocumentElement()
                );
            m_metadata->init();

            config = data_path + "FilesystemCredentialResolver.xml";
            ifstream in2(config.c_str());
            DOMDocument* doc2=XMLToolingConfig::getConfig().getParser().parse(in2);
            XercesJanitor<DOMDocument> janitor2(doc2);
            m_creds = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
                FILESYSTEM_CREDENTIAL_RESOLVER,doc2->getDocumentElement()
                );
                
            m_trust = dynamic_cast<X509TrustEngine*>(
                SAMLConfig::getConfig().TrustEngineManager.newPlugin(EXPLICIT_KEY_SAMLTRUSTENGINE, NULL)
                );
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            tearDown();
            throw;
        }

    }
    
    void tearDown() {
        delete m_creds;
        delete m_metadata;
        delete m_trust;
        m_creds=NULL;
        m_metadata=NULL;
        m_trust=NULL;
        m_fields.clear();
        m_headers.clear();
        m_method.erase();
        m_url.erase();
    }

    // HTTPRequest methods

    const char* getMethod() const {
        return m_method.c_str();
    } 

    const char* getRequestURL() const {
        return m_url.c_str();
    }
    
    const char* getRequestBody() const {
        return NULL;
    }
    
    const char* getQueryString() const {
        return NULL;
    }
    
    string getRemoteUser() const {
        return "";
    }

    string getHeader(const char* name) const {
        map<string,string>::const_iterator i=m_headers.find(name);
        return i==m_headers.end() ? "" : i->second;
    }
    
    const char* getParameter(const char* name) const {
        map<string,string>::const_iterator i=m_fields.find(name);
        return i==m_fields.end() ? NULL : i->second.c_str();
    }

    vector<const char*>::size_type getParameters(const char* name, vector<const char*>& values) const {
        values.clear();
        map<string,string>::const_iterator i=m_fields.find(name);
        if (i!=m_fields.end())
            values.push_back(i->second.c_str());
        return values.size();
    }
    
    // HTTPResponse methods
    
    void setHeader(const char* name, const char* value) {
        m_headers[name] = value ? value : "";
    }
    
    void setCookie(const char* name, const char* value) {
        m_headers["Set-Cookie"] = string(name) + "=" + (value ? value : "");
    }
    
    // The amount of error checking missing from this is incredible, but as long
    // as the test data isn't unexpected or malformed, it should work.
    
    long sendRedirect(const char* url) {
        m_method = "GET";
        char* dup = strdup(url);
        char* pch = strchr(dup,'?');
        if (pch) {
            *pch++=0;
            char* name=pch;
            while (name && *name) {
                pch=strchr(pch,'=');
                *pch++=0;
                char* value=pch;
                pch=strchr(pch,'&');
                if (pch)
                    *pch++=0;
                SAMLConfig::getConfig().getURLEncoder()->decode(value);
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
    
    long sendResponse(std::istream& inputStream, int status = 200, const char* contentType = "text/html") {
        m_method="POST";
        string page,line;
        while (getline(inputStream,line))
            page += line + '\n';
            
        const char* pch=strstr(page.c_str(),"action=\"");
        pch+=strlen("action=\"");
        m_url = html_decode(page.substr(pch-page.c_str(),strchr(pch,'"')-pch));

        while (pch=strstr(pch,"<input type=\"hidden\" name=\"")) {
            pch+=strlen("<input type=\"hidden\" name=\"");
            string name = page.substr(pch-page.c_str(),strchr(pch,'"')-pch);
            pch=strstr(pch,"value=\"");
            pch+=strlen("value=\"");
            m_fields[name] = html_decode(page.substr(pch-page.c_str(),strchr(pch,'"')-pch));
        }
        return m_fields.size();
    }
};
