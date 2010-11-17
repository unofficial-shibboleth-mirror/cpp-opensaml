/*
 *  Copyright 2010 Internet2
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
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
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
    disco(m_feed, dynamic_cast<const EntitiesDescriptor*>(object), first);
    disco(m_feed, dynamic_cast<const EntityDescriptor*>(object), first);

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

void DiscoverableMetadataProvider::disco(string& s, const EntityDescriptor* entity, bool& first) const
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
            for (vector<IDPSSODescriptor*>::const_iterator idp = idps.begin(); !extFound && idp != idps.end(); ++idp) {
                if ((*idp)->isValid(now) && (*idp)->getExtensions()) {
                    const vector<XMLObject*>& exts =  const_cast<const Extensions*>((*idp)->getExtensions())->getUnknownXMLObjects();
                    for (vector<XMLObject*>::const_iterator ext = exts.begin(); !extFound && ext != exts.end(); ++ext) {
                        const UIInfo* info = dynamic_cast<UIInfo*>(*ext);
                        if (info) {
                            extFound = true;
                            const vector<DisplayName*>& dispnames = info->getDisplayNames();
                            if (!dispnames.empty()) {
                                s += ",\n \"DisplayNames\": [";
                                for (vector<DisplayName*>::const_iterator dispname = dispnames.begin(); dispname != dispnames.end(); ++dispname) {
                                    if (dispname != dispnames.begin())
                                        s += ',';
                                    auto_arrayptr<char> val(toUTF8((*dispname)->getName()));
                                    auto_ptr_char lang((*dispname)->getLang());
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
                                for (vector<Description*>::const_iterator desc = descs.begin(); desc != descs.end(); ++desc) {
                                    if (desc != descs.begin())
                                        s += ',';
                                    auto_arrayptr<char> val(toUTF8((*desc)->getDescription()));
                                    auto_ptr_char lang((*desc)->getLang());
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
                                for (vector<Keywords*>::const_iterator words = keywords.begin(); words != keywords.end(); ++words) {
                                    if (words != keywords.begin())
                                        s += ',';
                                    auto_arrayptr<char> val(toUTF8((*words)->getValues()));
                                    auto_ptr_char lang((*words)->getLang());
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
                                for (vector<InformationURL*>::const_iterator infurl = infurls.begin(); infurl != infurls.end(); ++infurl) {
                                    if (infurl != infurls.begin())
                                        s += ',';
                                    auto_ptr_char val((*infurl)->getURL());
                                    auto_ptr_char lang((*infurl)->getLang());
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
                                for (vector<PrivacyStatementURL*>::const_iterator priv = privs.begin(); priv != privs.end(); ++priv) {
                                    if (priv != privs.begin())
                                        s += ',';
                                    auto_ptr_char val((*priv)->getURL());
                                    auto_ptr_char lang((*priv)->getLang());
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
                                for (vector<Logo*>::const_iterator logo = logos.begin(); logo != logos.end(); ++logo) {
                                    if (logo != logos.begin())
                                        s += ',';
                                    s += "\n  {\n";
                                    auto_ptr_char val((*logo)->getURL());
                                    s += "  \"value\": \"";
                                    json_safe(s, val.get());
                                    ostringstream ht;
                                    ht << (*logo)->getHeight().second;
                                    s += "\",\n  \"height\": \"";
                                    s += ht.str();
                                    ostringstream wt;
                                    wt << (*logo)->getWidth().second;
                                    s += "\",\n  \"width\": \"";
                                    s += wt.str();
                                    s += '\"';
                                    if ((*logo)->getLang()) {
                                        auto_ptr_char lang((*logo)->getLang());
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
                for (vector<IDPSSODescriptor*>::const_iterator idp = idps.begin(); !org && idp != idps.end(); ++idp) {
                    if ((*idp)->isValid(now))
                        org = (*idp)->getOrganization();
                }
                if (!org)
                    org = entity->getOrganization();
                if (org) {
                    const vector<OrganizationDisplayName*>& odns = org->getOrganizationDisplayNames();
                    if (!odns.empty()) {
                        s += ",\n \"DisplayNames\": [";
                        for (vector<OrganizationDisplayName*>::const_iterator dispname = odns.begin(); dispname != odns.end(); ++dispname) {
                            if (dispname != odns.begin())
                                s += ',';
                            auto_arrayptr<char> val(toUTF8((*dispname)->getName()));
                            auto_ptr_char lang((*dispname)->getLang());
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

void DiscoverableMetadataProvider::disco(string& s, const EntitiesDescriptor* group, bool& first) const
{
    if (group) {
        const vector<EntitiesDescriptor*>& groups = group->getEntitiesDescriptors();
        for (vector<EntitiesDescriptor*>::const_iterator i = groups.begin(); i != groups.end(); ++i)
            disco(s, *i, first);

        const vector<EntityDescriptor*>& sites = group->getEntityDescriptors();
        for (vector<EntityDescriptor*>::const_iterator j = sites.begin(); j != sites.end(); ++j)
            disco(s, *j, first);
    }
}
