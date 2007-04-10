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
 * ContentReference.cpp
 * 
 * SAML-specific signature reference profile 
 */
 
#include "internal.h"
#include "signature/ContentReference.h"
#include "signature/SignableObject.h"

#include <xmltooling/signature/Signature.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGTransformC14n.hpp>

using namespace opensaml;
using namespace xmltooling;
using namespace std;

void ContentReference::createReferences(DSIGSignature* sig)
{
    DSIGReference* ref=NULL;
    const XMLCh* id=m_signableObject.getXMLID();
    if (!id || !*id)
        ref=sig->createReference(&chNull);  // whole doc reference
    else {
        XMLCh* buf=new XMLCh[XMLString::stringLen(id) + 2];
        buf[0]=chPound;
        buf[1]=chNull;
        XMLString::catString(buf,id);
        try {
            ref=sig->createReference(buf, m_digest ? m_digest : DSIGConstants::s_unicodeStrURISHA1);
            delete[] buf;
        }
        catch(...) {
            delete[] buf;
            throw;
        }
    }
    
    ref->appendEnvelopedSignatureTransform();
    DSIGTransformC14n* c14n=ref->appendCanonicalizationTransform(m_c14n ? m_c14n : DSIGConstants::s_unicodeStrURIEXC_C14N_NOC);
    if (!m_c14n || m_c14n == DSIGConstants::s_unicodeStrURIEXC_C14N_NOC || m_c14n == DSIGConstants::s_unicodeStrURIEXC_C14N_COM) {
        addPrefixes(m_signableObject);
#ifdef HAVE_GOOD_STL
        xstring prefixes;
        for (set<xstring>::const_iterator p = m_prefixes.begin(); p!=m_prefixes.end(); ++p)
            prefixes += *p + chSpace;
        if (!prefixes.empty()) {
            prefixes.erase(prefixes.begin() + prefixes.size() - 1);
            c14n->setInclusiveNamespaces(XMLString::replicate(prefixes.c_str()));
        }
#else
        for (set<string>::const_iterator p = m_prefixes.begin(); p!=m_prefixes.end(); ++p)
            c14n->addInclusiveNamespace(p->c_str());
#endif
    }
}

void ContentReference::addInclusivePrefix(const XMLCh* prefix)
{
    static const XMLCh _default[] = { chPound, chLatin_d, chLatin_e, chLatin_f, chLatin_a, chLatin_u, chLatin_l, chLatin_t, chNull };

#ifdef HAVE_GOOD_STL
    if (prefix && *prefix)
        m_prefixes.insert(prefix);
    else
        m_prefixes.insert(_default);
#else
    if (prefix && *prefix) {
        auto_ptr_char p(prefix);
        m_prefixes.insert(p.get());
    }
    else
        m_prefixes.insert("#default");
#endif
}

void ContentReference::addPrefixes(const std::set<Namespace>& namespaces)
{
    for (set<Namespace>::const_iterator n = namespaces.begin(); n!=namespaces.end(); ++n)
        addInclusivePrefix(n->getNamespacePrefix());
}

void ContentReference::addPrefixes(const XMLObject& xmlObject)
{
    addPrefixes(xmlObject.getNamespaces());
    const list<XMLObject*>& children = xmlObject.getOrderedChildren();
    for (list<XMLObject*>::const_iterator child = children.begin(); child!=children.end(); ++child) {
        if (*child)
            addPrefixes(*(*child));
    }
}
