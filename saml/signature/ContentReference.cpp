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
 * ContentReference.cpp
 * 
 * SAML-specific signature reference profile.
 */
 
#include "internal.h"
#include "signature/ContentReference.h"
#include "signature/SignableObject.h"

#include <xmltooling/signature/Signature.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
#include <xsec/dsig/DSIGTransformC14n.hpp>

using namespace opensaml;
using namespace xmltooling;
using namespace std;

ContentReference::ContentReference(const SignableObject& signableObject)
    : m_signableObject(signableObject), m_digest(nullptr), m_c14n(nullptr)
{
}

ContentReference::~ContentReference()
{
}

void ContentReference::createReferences(DSIGSignature* sig)
{
    DSIGReference* ref = nullptr;
    const XMLCh* id=m_signableObject.getXMLID();
    if (!id || !*id)
        ref=sig->createReference(&chNull, m_digest ? m_digest : DSIGConstants::s_unicodeStrURISHA1);  // whole doc reference
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
        // Compute inclusive prefix set.
        set<xstring> prefix_set;
        XMLHelper::getNonVisiblyUsedPrefixes(m_signableObject, prefix_set);
        prefix_set.insert(m_prefixes.begin(), m_prefixes.end());

        // Build up the string of prefixes.
        xstring prefixes;
        static const XMLCh _default[] = { chPound, chLatin_d, chLatin_e, chLatin_f, chLatin_a, chLatin_u, chLatin_l, chLatin_t, chNull };
        for (set<xstring>::const_iterator p = prefix_set.begin(); p != prefix_set.end(); ++p) {
            prefixes += (p->empty() ? _default : p->c_str());
            prefixes += chSpace;
        }
        if (!prefixes.empty()) {
            prefixes.erase(prefixes.begin() + prefixes.size() - 1);
            c14n->setInclusiveNamespaces(prefixes.c_str());
        }
    }
}

void ContentReference::addInclusivePrefix(const XMLCh* prefix)
{
    m_prefixes.insert(prefix ? prefix : &chNull);
}

void ContentReference::setDigestAlgorithm(const XMLCh* digest)
{
    m_digest = digest;
}

void ContentReference::setCanonicalizationMethod(const XMLCh* c14n)
{
    m_c14n = c14n;
}
