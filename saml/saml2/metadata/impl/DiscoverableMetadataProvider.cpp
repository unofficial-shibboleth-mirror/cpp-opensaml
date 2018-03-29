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
 * DiscoverableMetadataProvider.cpp
 *
 * A metadata provider that provides a JSON feed of IdP discovery information.
 */

#include "internal.h"
#include "binding/SAMLArtifact.h"
#include "saml2/metadata/EntityMatcher.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/DiscoverableMetadataProvider.h"

#include <fstream>
#include <sstream>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/casts.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>

using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;

DiscoverableMetadataProvider::DiscoverableMetadataProvider(const DOMElement* e) : MetadataProvider(e), m_legacyOrgNames(false)
{
    static const XMLCh legacyOrgNames[] =   UNICODE_LITERAL_14(l,e,g,a,c,y,O,r,g,N,a,m,e,s);
    static const XMLCh matcher[] =          UNICODE_LITERAL_7(m,a,t,c,h,e,r);
    static const XMLCh tagsInFeed[] =       UNICODE_LITERAL_10(t,a,g,s,I,n,F,e,e,d);
    static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh DiscoveryFilter[] =  UNICODE_LITERAL_15(D,i,s,c,o,v,e,r,y,F,i,l,t,e,r);

    const XMLCh* attrib = e? e->getAttributeNS(nullptr, legacyOrgNames) : nullptr;
    if (attrib && *attrib) {
        Category::getInstance(SAML_LOGCAT ".MetadataProvider.Discoverable").warn("legacyOrgNames is a deprecated attribute for MetadataProviders");
    }

    m_legacyOrgNames = XMLHelper::getAttrBool(e, false, legacyOrgNames);
    m_entityAttributes = XMLHelper::getAttrBool(e, false, tagsInFeed);

    e = e ? XMLHelper::getFirstChildElement(e, DiscoveryFilter) : nullptr;
    while (e) {
        string t(XMLHelper::getAttrString(e, nullptr, _type));
        if (t == "Whitelist" || t == "Blacklist") {
            string m(XMLHelper::getAttrString(e, nullptr, matcher));
            if (!m.empty()) {
                try {
                    boost::shared_ptr<EntityMatcher> temp(SAMLConfig::getConfig().EntityMatcherManager.newPlugin(m, e));
                    m_discoFilters.push_back(make_pair(t == "Whitelist", temp));
                }
                catch (std::exception& ex) {
                    Category::getInstance(SAML_LOGCAT ".MetadataProvider.Discoverable").error(
                        "exception creating <DiscoveryFilter> EntityMatcher: %s", ex.what()
                        );
                }
            }
            else {
                Category::getInstance(SAML_LOGCAT ".MetadataProvider.Discoverable").error("<DiscoveryFilter> requires matcher attribute");
            }
        }
        else {
            Category::getInstance(SAML_LOGCAT ".MetadataProvider.Discoverable").error(
                "unknown <DiscoveryFilter> type (%s)", t.empty() ? "none" : t.c_str()
                );
        }
        e = XMLHelper::getNextSiblingElement(e, DiscoveryFilter);
    }
}

DiscoverableMetadataProvider::~DiscoverableMetadataProvider()
{
}

void DiscoverableMetadataProvider::generateFeed()
{
    m_feed.erase();
    bool first = true;
    const XMLObject* object = getMetadata();
    discoGroup(m_feed, dynamic_cast<const EntitiesDescriptor*>(object), first);
    discoEntity(m_feed, dynamic_cast<const EntityDescriptor*>(object), first);

    SAMLConfig::getConfig().generateRandomBytes(m_feedTag, 4);
    m_feedTag = SAMLArtifact::toHex(m_feedTag);
}

string DiscoverableMetadataProvider::getCacheTag() const
{
    return m_feedTag;
}

void DiscoverableMetadataProvider::outputFeed(ostream& os, bool& first, bool wrapArray) const
{
    if (wrapArray)
        os << '[';
    if (!m_feed.empty()) {
        if (first)
            first = false;
        else
            os << ",\n";
        os << m_feed;
    }
    if (wrapArray)
        os << "\n]";
}

namespace {
    static string& json_safe(string& s, const char* buf)
    {
        for (; *buf; ++buf) {
            switch (*buf) {
                case '\\':
                case '"':
                    s += '\\';
                    s += *buf;
                    break;
                case '\b':
                    s += "\\b";
                    break;
                case '\t':
                    s += "\\t";
                    break;
                case '\n':
                    s += "\\n";
                    break;
                case '\f':
                    s += "\\f";
                    break;
                case '\r':
                    s += "\\r";
                    break;
                default:
                    s += *buf;
            }
        }
        return s;
    }
};

void DiscoverableMetadataProvider::discoEntity(string& s, const EntityDescriptor* entity, bool& first) const
{
    time_t now = time(nullptr);
    if (entity && entity->isValid(now)) {

        // Check filter(s).
        for (vector< pair < bool, boost::shared_ptr<EntityMatcher> > >::const_iterator f = m_discoFilters.begin(); f != m_discoFilters.end(); ++f) {
            // The flag is true for a whitelist and false for a blacklist,
            // so we omit the entity if the match outcome is the inverse.
            if (f->first != f->second->matches(*entity))
                return;
        }

        const vector<IDPSSODescriptor*>& idps = entity->getIDPSSODescriptors();
        if (!idps.empty()) {
            auto_ptr_char entityid(entity->getEntityID());
            // Open a struct and output id: entityID.
            if (first)
                first = false;
            else
                s += ',';
            s += "\n{\n \"entityID\": \"";
            json_safe(s, entityid.get());
            s += '\"';
            bool extFound = false;
            bool displayNameFound = false;
            for (indirect_iterator<vector<IDPSSODescriptor*>::const_iterator> idp = make_indirect_iterator(idps.begin());
                    !extFound && idp != make_indirect_iterator(idps.end()); ++idp) {
                if (idp->isValid(now) && idp->getExtensions()) {
                    const vector<XMLObject*>& exts =  const_cast<const Extensions*>(idp->getExtensions())->getUnknownXMLObjects();
                    for (vector<XMLObject*>::const_iterator ext = exts.begin(); !extFound && ext != exts.end(); ++ext) {
                        const UIInfo* info = dynamic_cast<UIInfo*>(*ext);
                        if (info) {
                            extFound = true;
                            const vector<DisplayName*>& dispnames = info->getDisplayNames();
                            if (!dispnames.empty()) {
                                displayNameFound = true;
                                s += ",\n \"DisplayNames\": [";
                                for (indirect_iterator<vector<DisplayName*>::const_iterator> dispname = make_indirect_iterator(dispnames.begin());
                                        dispname != make_indirect_iterator(dispnames.end()); ++dispname) {
                                    if (dispname.base() != dispnames.begin())
                                        s += ',';
                                    auto_arrayptr<char> val(toUTF8(dispname->getName()));
                                    auto_ptr_char lang(dispname->getLang());
                                    s += "\n  {\n  \"value\": \"";
                                    json_safe(s, val.get());
                                    s += "\",\n  \"lang\": \"";
                                    s += lang.get();
                                    s += "\"\n  }";
                                }
                                s += "\n ]";
                            }

                            const vector<Description*>& descs = info->getDescriptions();
                            if (!descs.empty()) {
                                s += ",\n \"Descriptions\": [";
                                for (indirect_iterator<vector<Description*>::const_iterator> desc = make_indirect_iterator(descs.begin());
                                        desc != make_indirect_iterator(descs.end()); ++desc) {
                                    if (desc.base() != descs.begin())
                                        s += ',';
                                    auto_arrayptr<char> val(toUTF8(desc->getDescription()));
                                    auto_ptr_char lang(desc->getLang());
                                    s += "\n  {\n  \"value\": \"";
                                    json_safe(s, val.get());
                                    s += "\",\n  \"lang\": \"";
                                    s += lang.get();
                                    s += "\"\n  }";
                                }
                                s += "\n ]";
                            }

                            const vector<Keywords*>& keywords = info->getKeywordss();
                            if (!keywords.empty()) {
                                s += ",\n \"Keywords\": [";
                                for (indirect_iterator<vector<Keywords*>::const_iterator> words = make_indirect_iterator(keywords.begin());
                                        words != make_indirect_iterator(keywords.end()); ++words) {
                                    if (words.base() != keywords.begin())
                                        s += ',';
                                    auto_arrayptr<char> val(toUTF8(words->getValues()));
                                    auto_ptr_char lang(words->getLang());
                                    s += "\n  {\n  \"value\": \"";
                                    json_safe(s, val.get());
                                    s += "\",\n  \"lang\": \"";
                                    s += lang.get();
                                    s += "\"\n  }";
                                }
                                s += "\n ]";
                            }

                            const vector<InformationURL*>& infurls = info->getInformationURLs();
                            if (!infurls.empty()) {
                                s += ",\n \"InformationURLs\": [";
                                for (indirect_iterator<vector<InformationURL*>::const_iterator> infurl = make_indirect_iterator(infurls.begin());
                                        infurl != make_indirect_iterator(infurls.end()); ++infurl) {
                                    if (infurl.base() != infurls.begin())
                                        s += ',';
                                    auto_ptr_char val(infurl->getURL());
                                    auto_ptr_char lang(infurl->getLang());
                                    s += "\n  {\n  \"value\": \"";
                                    json_safe(s, val.get());
                                    s += "\",\n  \"lang\": \"";
                                    s += lang.get();
                                    s += "\"\n  }";
                                }
                                s += "\n ]";
                            }

                            const vector<PrivacyStatementURL*>& privs = info->getPrivacyStatementURLs();
                            if (!privs.empty()) {
                                s += ",\n \"PrivacyStatementURLs\": [";
                                for (indirect_iterator<vector<PrivacyStatementURL*>::const_iterator> priv = make_indirect_iterator(privs.begin());
                                        priv != make_indirect_iterator(privs.end()); ++priv) {
                                    if (priv.base() != privs.begin())
                                        s += ',';
                                    auto_ptr_char val(priv->getURL());
                                    auto_ptr_char lang(priv->getLang());
                                    s += "\n  {\n  \"value\": \"";
                                    json_safe(s, val.get());
                                    s += "\",\n  \"lang\": \"";
                                    s += lang.get();
                                    s += "\"\n  }";
                                }
                                s += "\n ]";
                            }

                            const vector<Logo*>& logos = info->getLogos();
                            if (!logos.empty()) {
                                s += ",\n \"Logos\": [";
                                for (indirect_iterator<vector<Logo*>::const_iterator> logo = make_indirect_iterator(logos.begin());
                                        logo != make_indirect_iterator(logos.end()); ++logo) {
                                    if (logo.base() != logos.begin())
                                        s += ',';
                                    s += "\n  {\n";
                                    auto_ptr_char val(logo->getURL());
                                    s += "  \"value\": \"";
                                    json_safe(s, val.get());
                                    ostringstream ht;
                                    ht << logo->getHeight().second;
                                    s += "\",\n  \"height\": \"";
                                    s += ht.str();
                                    ostringstream wt;
                                    wt << logo->getWidth().second;
                                    s += "\",\n  \"width\": \"";
                                    s += wt.str();
                                    s += '\"';
                                    if (logo->getLang()) {
                                        auto_ptr_char lang(logo->getLang());
                                        s += ",\n  \"lang\": \"";
                                        s += lang.get();
                                        s += '\"';
                                    }
                                    s += "\n  }";
                                }
                                s += "\n ]";
                            }
                        }
                    }
                }
            }

            if (m_legacyOrgNames && !displayNameFound) {
                const Organization* org = nullptr;
                for (indirect_iterator<vector<IDPSSODescriptor*>::const_iterator> idp = make_indirect_iterator(idps.begin());
                        !org && idp != make_indirect_iterator(idps.end()); ++idp) {
                    if (idp->isValid(now))
                        org = idp->getOrganization();
                }
                if (!org)
                    org = entity->getOrganization();
                if (org) {
                    const vector<OrganizationDisplayName*>& odns = org->getOrganizationDisplayNames();
                    if (!odns.empty()) {
                        s += ",\n \"DisplayNames\": [";
                        for (indirect_iterator<vector<OrganizationDisplayName*>::const_iterator> dispname = make_indirect_iterator(odns.begin());
                                dispname != make_indirect_iterator(odns.end()); ++dispname) {
                            if (dispname.base() != odns.begin())
                                s += ',';
                            auto_arrayptr<char> val(toUTF8(dispname->getName()));
                            auto_ptr_char lang(dispname->getLang());
                            s += "\n  {\n  \"value\": \"";
                            json_safe(s, val.get());
                            s += "\",\n  \"lang\": \"";
                            s += lang.get();
                            s += "\"\n  }";
                        }
                        s += "\n ]";
                    }
                }
            }

            if (m_entityAttributes) {
                bool tagfirst = true;
                // Check for an EntityAttributes extension in the entity and its parent(s).
                const Extensions* exts = entity->getExtensions();
                if (exts) {
                    const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
                    const XMLObject* xo = find_if(children, ll_dynamic_cast<EntityAttributes*>(_1) != ((EntityAttributes*)nullptr));
                    if (xo)
                        discoEntityAttributes(s, *dynamic_cast<const EntityAttributes*>(xo), tagfirst);
                }

                const EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(entity->getParent());
                while (group) {
                    exts = group->getExtensions();
                    if (exts) {
                        const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
                        const XMLObject* xo = find_if(children, ll_dynamic_cast<EntityAttributes*>(_1) != ((EntityAttributes*)nullptr));
                        if (xo)
                            discoEntityAttributes(s, *dynamic_cast<const EntityAttributes*>(xo), tagfirst);
                    }
                    group = dynamic_cast<EntitiesDescriptor*>(group->getParent());
                }
                if (!tagfirst)
                    s += "\n ]";
            }

            // Close the struct;
            s += "\n}";
        }
    }
}

void DiscoverableMetadataProvider::discoGroup(string& s, const EntitiesDescriptor* group, bool& first) const
{
    if (group) {
        for_each(
            group->getEntitiesDescriptors().begin(), group->getEntitiesDescriptors().end(),
            lambda::bind(&DiscoverableMetadataProvider::discoGroup, this, boost::ref(s), _1, boost::ref(first))
            );
        for_each(
            group->getEntityDescriptors().begin(), group->getEntityDescriptors().end(),
            lambda::bind(&DiscoverableMetadataProvider::discoEntity, this, boost::ref(s), _1, boost::ref(first))
            );
    }
}

void DiscoverableMetadataProvider::discoEntityAttributes(std::string& s, const EntityAttributes& ea, bool& first) const
{
    discoAttributes(s, ea.getAttributes(), first);
    const vector<saml2::Assertion*>& tokens = ea.getAssertions();
    for (vector<saml2::Assertion*>::const_iterator t = tokens.begin(); t != tokens.end(); ++t) {
        const vector<AttributeStatement*> statements = const_cast<const saml2::Assertion*>(*t)->getAttributeStatements();
        for (vector<AttributeStatement*>::const_iterator st = statements.begin(); st != statements.end(); ++st) {
            discoAttributes(s, const_cast<const AttributeStatement*>(*st)->getAttributes(), first);
        }
    }
}

void DiscoverableMetadataProvider::discoAttributes(std::string& s, const vector<Attribute*>& attrs, bool& first) const
{
    for (indirect_iterator<vector<Attribute*>::const_iterator> a = make_indirect_iterator(attrs.begin());
            a != make_indirect_iterator(attrs.end()); ++a) {

        if (first) {
            s += ",\n \"EntityAttributes\": [";
            first = false;
        }
        else {
            s += ',';
        }

        auto_ptr_char n(a->getName());
        s += "\n  {\n  \"name\": \"";
        json_safe(s, n.get());
        s += "\",\n  \"values\": [";
        const vector<XMLObject*>& vals = const_cast<const Attribute&>(*a).getAttributeValues();
        for (indirect_iterator<vector<XMLObject*>::const_iterator> v = make_indirect_iterator(vals.begin());
                v != make_indirect_iterator(vals.end()); ++v) {
            if (v.base() != vals.begin())
                s += ',';
            auto_arrayptr<char> val(toUTF8(v->getTextContent()));
            s += "\n     \"";
            if (val.get())
                json_safe(s, val.get());
            s += '\"';
        }
        s += "\n  ]\n  }";
    }
}
