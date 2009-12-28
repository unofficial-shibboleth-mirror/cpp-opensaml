
AUTOMAKE_OPTIONS = foreign

pkgxmldir = $(datadir)/xml/@PACKAGE@

schemafiles = \
	cs-sstc-schema-assertion-01.xsd \
	cs-sstc-schema-protocol-01.xsd \
	cs-sstc-schema-assertion-1.1.xsd \
	cs-sstc-schema-protocol-1.1.xsd \
	saml-schema-assertion-2.0.xsd \
	saml-schema-authn-context-2.0.xsd \
	saml-schema-authn-context-auth-telephony-2.0.xsd \
	saml-schema-authn-context-ip-2.0.xsd \
	saml-schema-authn-context-ippword-2.0.xsd \
	saml-schema-authn-context-kerberos-2.0.xsd \
	saml-schema-authn-context-mobileonefactor-reg-2.0.xsd \
	saml-schema-authn-context-mobileonefactor-unreg-2.0.xsd \
	saml-schema-authn-context-mobiletwofactor-reg-2.0.xsd \
	saml-schema-authn-context-mobiletwofactor-unreg-2.0.xsd \
	saml-schema-authn-context-nomad-telephony-2.0.xsd \
	saml-schema-authn-context-personal-telephony-2.0.xsd \
	saml-schema-authn-context-pgp-2.0.xsd \
	saml-schema-authn-context-ppt-2.0.xsd \
	saml-schema-authn-context-pword-2.0.xsd \
	saml-schema-authn-context-session-2.0.xsd \
	saml-schema-authn-context-smartcard-2.0.xsd \
	saml-schema-authn-context-smartcardpki-2.0.xsd \
	saml-schema-authn-context-softwarepki-2.0.xsd \
	saml-schema-authn-context-spki-2.0.xsd \
	saml-schema-authn-context-srp-2.0.xsd \
	saml-schema-authn-context-sslcert-2.0.xsd \
	saml-schema-authn-context-telephony-2.0.xsd \
	saml-schema-authn-context-timesync-2.0.xsd \
	saml-schema-authn-context-types-2.0.xsd \
	saml-schema-authn-context-x509-2.0.xsd \
	saml-schema-authn-context-xmldsig-2.0.xsd \
	saml-schema-dce-2.0.xsd \
	saml-schema-ecp-2.0.xsd \
	saml-schema-metadata-2.0.xsd \
	saml-schema-protocol-2.0.xsd \
	saml-schema-x500-2.0.xsd \
	saml-schema-xacml-2.0.xsd \
	sstc-metadata-attr.xsd \
	sstc-saml1x-metadata.xsd \
	sstc-saml-attribute-ext.xsd \
	sstc-saml-delegation.xsd \
	sstc-saml-metadata-ext-query.xsd \
	sstc-saml-protocol-ext-thirdparty.xsd

pkgxml_DATA = \
	saml20-catalog.xml \
	saml10-catalog.xml \
	saml11-catalog.xml \
	$(schemafiles)

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${srcdir}/${FILE}.in > ${FILE}.tmp \
	    -e 's:@-PKGXMLDIR-@:${pkgxmldir}:g'
	cmp -s ${FILE} ${FILE}.tmp || mv ${FILE}.tmp ${FILE}
	rm -f ${FILE}.tmp

saml20-catalog.xml: ${srcdir}/saml20-catalog.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

saml10-catalog.xml: ${srcdir}/saml10-catalog.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

saml11-catalog.xml: ${srcdir}/saml11-catalog.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

CLEANFILES = \
	saml20-catalog.xml \
	saml10-catalog.xml \
	saml11-catalog.xml

EXTRA_DIST = \
	saml20-catalog.xml.in \
	saml10-catalog.xml.in \
	saml11-catalog.xml.in \
	$(schemafiles)
