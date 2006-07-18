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
 * SAMLConstants.cpp
 * 
 * SAML XML namespace constants 
 */


#include "internal.h"
#include "util/SAMLConstants.h"
#include <xercesc/util/XMLUniDefs.hpp>

using namespace xercesc;
using namespace opensaml;

const XMLCh SAMLConstants::SOAP11ENV_NS[] = // http://schemas.xmlsoap.org/soap/envelope/
{ chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash, chForwardSlash,
  chLatin_s, chLatin_c, chLatin_h, chLatin_e, chLatin_m, chLatin_a, chLatin_s, chPeriod,
      chLatin_x, chLatin_m, chLatin_l, chLatin_s, chLatin_o, chLatin_a, chLatin_p, chPeriod,
      chLatin_o, chLatin_r, chLatin_g, chForwardSlash,
  chLatin_s, chLatin_o, chLatin_a, chLatin_p, chForwardSlash,
  chLatin_e, chLatin_n, chLatin_v, chLatin_e, chLatin_l, chLatin_o, chLatin_p, chLatin_e, chForwardSlash, chNull
};

const XMLCh SAMLConstants::SOAP11ENV_PREFIX[] = UNICODE_LITERAL_1(S);

const XMLCh SAMLConstants::PAOS_NS[] = // urn:liberty:paos:2003-08
{ chLatin_u, chLatin_r, chLatin_n, chColon,
  chLatin_l, chLatin_i, chLatin_b, chLatin_e, chLatin_r, chLatin_t, chLatin_y, chColon,
  chLatin_p, chLatin_a, chLatin_o, chLatin_s, chColon,
  chDigit_2, chDigit_0, chDigit_0, chDigit_3, chDash, chDigit_0, chDigit_8, chNull
};

const XMLCh SAMLConstants::PAOS_PREFIX[] = UNICODE_LITERAL_4(p,a,o,s);

const XMLCh SAMLConstants::SAML1_NS[] = // urn:oasis:names:tc:SAML:1.0:assertion
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh SAMLConstants::SAML1P_NS[] = // urn:oasis:names:tc:SAML:1.0:protocol
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chNull
};

const XMLCh SAMLConstants::SAML1_PREFIX[] = UNICODE_LITERAL_4(s,a,m,l);

const XMLCh SAMLConstants::SAML1P_PREFIX[] = UNICODE_LITERAL_5(s,a,m,l,p);

const XMLCh SAMLConstants::SAML11_PROTOCOL_ENUM[] = // urn:oasis:names:tc:SAML:1.1:protocol
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chNull
};

const XMLCh SAMLConstants::SAML1_METADATA_PROFILE[] = // urn:oasis:names:tc:SAML:profiles:v1metadata
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_v, chDigit_1, chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chNull
};

const XMLCh SAMLConstants::SAML20_VERSION[] = // 2.0
{ chDigit_2, chPeriod, chDigit_0, chNull
};

const XMLCh SAMLConstants::SAML20_NS[] = // urn:oasis:names:tc:SAML:2.0:assertion
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh SAMLConstants::SAML20P_NS[] = // urn:oasis:names:tc:SAML:2.0:protocol
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chNull
};

const XMLCh SAMLConstants::SAML20MD_NS[] = // urn:oasis:names:tc:SAML:2.0:metadata
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chNull
};

const XMLCh SAMLConstants::SAML20AC_NS[] = // urn:oasis:names:tc:SAML:2.0:ac
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_c, chNull
};

const XMLCh SAMLConstants::SAML20_PREFIX[] = UNICODE_LITERAL_4(s,a,m,l);

const XMLCh SAMLConstants::SAML20P_PREFIX[] = UNICODE_LITERAL_5(s,a,m,l,p);

const XMLCh SAMLConstants::SAML20MD_PREFIX[] = UNICODE_LITERAL_2(m,d);

const XMLCh SAMLConstants::SAML20AC_PREFIX[] = UNICODE_LITERAL_2(a,c);

const XMLCh SAMLConstants::SAML20ECP_NS[] = // urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_S, chLatin_S, chLatin_O, chColon, chLatin_e, chLatin_c, chLatin_p, chNull
};

const XMLCh SAMLConstants::SAML20ECP_PREFIX[] = UNICODE_LITERAL_3(e,c,p);

const XMLCh SAMLConstants::SAML20DCE_NS[] = // urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chColon,
  chLatin_D, chLatin_C, chLatin_E, chNull
};

const XMLCh SAMLConstants::SAML20DCE_PREFIX[] = UNICODE_LITERAL_3(D,C,E);

const XMLCh SAMLConstants::SAML20X500_NS[] = // urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chColon,
  chLatin_X, chDigit_5, chDigit_0, chDigit_0, chNull
};

const XMLCh SAMLConstants::SAML20X500_PREFIX[] = { chLatin_x, chDigit_5, chDigit_0, chDigit_0 };

const XMLCh SAMLConstants::SAML20XACML_NS[] = // urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chColon,
  chLatin_X, chLatin_A, chLatin_C, chLatin_M, chLatin_L, chNull
};

const XMLCh SAMLConstants::SAML20XACML_PREFIX[] = UNICODE_LITERAL_9(x,a,c,m,l,p,r,o,f);
