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
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/DiscoverableMetadataProvider.h"

#include <fstream>
#include <sstream>
#include <boost/bind.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace boost;
using namespace std;

DiscoverableMetadataProvider::DiscoverableMetadataProvider(const DOMElement* e) : MetadataProvider(e), m_legacyOrgNames(false)
{
    static const XMLCh legacyOrgNames[] = UNICODE_LITERAL_14(l,e,g,a,c,y,O,r,g,N,a,m,e,s);
    m_legacyOrgNames = XMLHelper::getAttrBool(e, false, legacyOrgNames);
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

void DiscoverableMetadataProvider::discoEntity(string& s, const EntityDescriptor* entity, bool& first) const
{
    time_t now = time(nullptr);
    if (entity && entity->isValid(now)) {
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

            if (m_legacyOrgNames && !extFound) {
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
            boost::bind(&DiscoverableMetadataProvider::discoGroup, boost::ref(this), boost::ref(s), _1, boost::ref(first))
            );
        for_each(
            group->getEntityDescriptors().begin(), group->getEntityDescriptors().end(),
            boost::bind(&DiscoverableMetadataProvider::discoEntity, boost::ref(this), boost::ref(s), _1, boost::ref(first))
            );
    }
}
