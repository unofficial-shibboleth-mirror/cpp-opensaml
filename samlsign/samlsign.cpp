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

/* siterefresh.cpp - command-line tool to refresh and verify metadata

   Scott Cantor
   5/12/03

   $Id:siterefresh.cpp 2252 2007-05-20 20:20:57Z cantor $
*/

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/XMLHelper.h>

#include <fstream>
#include <xercesc/framework/LocalFileInputSource.hpp>
#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/framework/StdInInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>

using namespace xmlsignature;
using namespace xmlconstants;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace samlconstants;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xercesc;
using namespace std;

template<class T> T* buildPlugin(const char* path, PluginManager<T,string,const DOMElement*>& mgr)
{
    ifstream in(path);
    DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
    XercesJanitor<DOMDocument> janitor(doc);
    
    static const XMLCh _type[] = UNICODE_LITERAL_4(t,y,p,e);
    auto_ptr_char type(doc->getDocumentElement()->getAttributeNS(NULL,_type));
    if (type.get() && *type.get())
        return mgr.newPlugin(type.get(), doc->getDocumentElement());
    throw XMLToolingException("Missing type in plugin configuration.");
}

CredentialResolver* buildSimpleResolver(const char* key, const char* cert)
{
    static const XMLCh _CredentialResolver[] =  UNICODE_LITERAL_18(C,r,e,d,e,n,t,i,a,l,R,e,s,o,l,v,e,r);
    static const XMLCh _certificate[] =     UNICODE_LITERAL_11(c,e,r,t,i,f,i,c,a,t,e);
    static const XMLCh _key[] =             UNICODE_LITERAL_3(k,e,y);

    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().newDocument();
    XercesJanitor<DOMDocument> janitor(doc);
    DOMElement* root = doc->createElementNS(NULL, _CredentialResolver);
    if (key) {
        auto_ptr_XMLCh widenit(key);
        root->setAttributeNS(NULL, _key, widenit.get());
    }
    if (cert) {
        auto_ptr_XMLCh widenit(cert);
        root->setAttributeNS(NULL, _certificate, widenit.get());
    }

    return XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER, root);
}

int main(int argc,char* argv[])
{
    bool verify=true;
    char* url_param=NULL;
    char* path_param=NULL;
    char* key_param=NULL;
    char* cert_param=NULL;
    char* cr_param=NULL;
    char* t_param=NULL;
    char* id_param=NULL;

    // metadata lookup options
    char* m_param=NULL;
    char* issuer=NULL;
    char* prot = NULL;
    const XMLCh* protocol = NULL;
    char* rname = NULL;
    char* rns = NULL;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-u") && i+1<argc)
            url_param=argv[++i];
        else if (!strcmp(argv[i],"-f") && i+1<argc)
            path_param=argv[++i];
        else if (!strcmp(argv[i],"-id") && i+1<argc)
            id_param=argv[++i];
        else if (!strcmp(argv[i],"-s"))
            verify=false;
        else if (!strcmp(argv[i],"-k") && i+1<argc)
            key_param=argv[++i];
        else if (!strcmp(argv[i],"-c") && i+1<argc)
            cert_param=argv[++i];
        else if (!strcmp(argv[i],"-R") && i+1<argc)
            cr_param=argv[++i];
        else if (!strcmp(argv[i],"-T") && i+1<argc)
            t_param=argv[++i];
        else if (!strcmp(argv[i],"-M") && i+1<argc)
            m_param=argv[++i];
        else if (!strcmp(argv[i],"-i") && i+1<argc)
            issuer=argv[++i];
        else if (!strcmp(argv[i],"-p") && i+1<argc)
            prot=argv[++i];
        else if (!strcmp(argv[i],"-r") && i+1<argc)
            rname=argv[++i];
        else if (!strcmp(argv[i],"-ns") && i+1<argc)
            rns=argv[++i];
        else if (!strcmp(argv[i],"-saml10"))
            protocol=samlconstants::SAML10_PROTOCOL_ENUM;
        else if (!strcmp(argv[i],"-saml11"))
            protocol=samlconstants::SAML11_PROTOCOL_ENUM;
        else if (!strcmp(argv[i],"-saml2"))
            protocol=samlconstants::SAML20P_NS;
        else if (!strcmp(argv[i],"-idp"))
            rname="IDPSSODescriptor";
        else if (!strcmp(argv[i],"-aa"))
            rname="AttributeAuthorityDescriptor";
        else if (!strcmp(argv[i],"-pdp"))
            rname="PDPDescriptor";
        else if (!strcmp(argv[i],"-sp"))
            rname="SPSSODescriptor";
    }

    if (!verify && !key_param && !cr_param) {
        cerr << "either -k or -R option required when signing, see documentation for usage" << endl;
        return -1;
    }

    SAMLConfig& conf=SAMLConfig::getConfig();
    if (!conf.init())
        return -2;
    XMLToolingConfig& xmlconf = XMLToolingConfig::getConfig();
    Category& log = Category::getInstance("OpenSAML.Utility.SAMLSign");

    int ret = 0;

    try {
        // Parse the specified document.
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        DOMDocument* doc=NULL;
        if (url_param) {
            URLInputSource src(base,url_param);
            Wrapper4InputSource dsrc(&src,false);
            doc=xmlconf.getParser().parse(dsrc);
        }
        else if (path_param) {
            auto_ptr_XMLCh widenit(path_param);
            LocalFileInputSource src(base,widenit.get());
            Wrapper4InputSource dsrc(&src,false);
            doc=xmlconf.getParser().parse(dsrc);
        }
        else {
            StdInInputSource src;
            Wrapper4InputSource dsrc(&src,false);
            doc=xmlconf.getParser().parse(dsrc);
        }
    
        // Unmarshall it.
        XercesJanitor<DOMDocument> jan(doc);
        auto_ptr<XMLObject> sourcewrapper(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        jan.release();

        // Navigate to the selected node, or use the root if no ID specified.
        // Then make sure it's a SignableSAMLObject.
        XMLObject* source = sourcewrapper.get();
        if (id_param) {
            auto_ptr_XMLCh widenit(id_param);
            source = XMLHelper::getXMLObjectById(*source, widenit.get());
            if (!source)
                throw XMLToolingException("Element with ID ($1) not found.", params(1,id_param));
        }
        SignableObject* signable = dynamic_cast<SignableObject*>(source);
        if (!signable)
            throw XMLToolingException("Input is not a signable SAML object.");

        if (verify) {
        }
        else {
            // Build a resolver to supply a credential.
            auto_ptr<CredentialResolver> cr(
                cr_param ? buildPlugin(cr_param, xmlconf.CredentialResolverManager) : buildSimpleResolver(key_param, cert_param)
                );
            cr->lock();
            CredentialCriteria cc;
            cc.setUsage(CredentialCriteria::SIGNING_CREDENTIAL);
            const Credential* cred = cr->resolve(&cc);
            if (!cred)
                throw XMLSecurityException("Unable to resolve a signing credential.");

            // Attach new signature.
            Signature* sig = SignatureBuilder::buildSignature();
            signable->setSignature(sig);

            // Sign response while re-marshalling.
            vector<Signature*> sigs(1,sig);
            XMLHelper::serialize(signable->marshall((DOMDocument*)NULL,&sigs,cred), cout);
        }
    }
    catch(exception& e) {
        log.errorStream() << "caught an exception: " << e.what() << CategoryStream::ENDLINE;
        ret=-10;
    }
    catch(XMLException& e) {
        auto_ptr_char temp(e.getMessage());
        log.errorStream() << "caught a Xerces exception: " << temp.get() << CategoryStream::ENDLINE;
        ret=-20;
    }

    conf.term();
    return ret;
}
