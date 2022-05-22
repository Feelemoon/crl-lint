//import { buffer } from 'node:util';
import fs from 'node:fs';
import assert from 'node:assert';

import chai from 'chai';
const expect = chai.expect;
import jsrsasign from 'jsrsasign';

describe('RFC8603', function() {
   let crlFile = process.env.CRL_FILE || 'test.crl';
   let raw;
   before(function(done) {
      fs.readFile(crlFile, (err, buf) => {
         assert.equal(err, undefined);
         raw = buf;
         done();
      });
   });
   let pem;
   let der;
   before(function() {
      let str = raw.toString('utf8');
      if (/^-{5}BEGIN X509 CRL-{5}/.test(str)) {
         pem = str;
         let b64 = pem.replaceAll(/(^-{5}(BEGIN|END) X509 CRL-{5}|[\n\r])/gm, '');
         der = Buffer.from(b64, 'base64');
      }
      else {
         der = raw;
      }
   });
   let crl;
   let parsed;
   before(function() {
      crl = new jsrsasign.X509CRL(der.toString('hex'));
      // console.log(`crl: ${JSON.stringify(crl.getParam())}`);
      parsed = crl.getParam();
   });

   let crlIssuerCertFile = process.env.CRL_ISSUER_CERT || 'test.ca.crt.pem';
   let crlIssuerCert;
   let crlIssuerCertParams;
   before(function(done) {
      fs.readFile(crlIssuerCertFile, (err, buf) => {
         assert.equal(err, undefined);
         let str = buf.toString('utf8');
         if (/^-{5}BEGIN CERTIFICATE-{5}/.test(str)) {
            pem = str;
            let b64 = pem.replaceAll(/(^-{5}(BEGIN|END) CERTIFICATE-{5}|[\n\r])/gm, '');
            der = Buffer.from(b64, 'base64');
         }
         else {
            der = raw;
         }
         crlIssuerCert = new jsrsasign.X509(der.toString('hex'));
         crlIssuerCertParams = crlIssuerCert.getParam();
         done();
      });
   });

   let crlCaCertFile = process.env.CRL_CA_CERT || crlIssuerCertFile;
   let crlCaCert;
   let crlCaCertParams;
   before(function(done) {
      fs.readFile(crlCaCertFile, (err, buf) => {
         assert.equal(err, undefined);
         let str = buf.toString('utf8');
         if (/^-{5}BEGIN CERTIFICATE-{5}/.test(str)) {
            pem = str;
            let b64 = pem.replaceAll(/(^-{5}(BEGIN|END) CERTIFICATE-{5}|[\n\r])/gm, '');
            der = Buffer.from(b64, 'base64');
         }
         else {
            der = raw;
         }
         crlCaCert = new jsrsasign.X509(der.toString('hex'));
         crlCaCertParams = crlCaCert.getParam();
         done();
      });
   });

   describe('4. General Requirements and Assumptions', function() {
      /* The goal of this document is to define a base set of
      requirements for certificates and CRLs to support interoperability
      among CNSA Suite solutions. Specific communities, such as those
      associated with US National Security Systems, may define community
      profiles that further restrict certificate and CRL contents by
      mandating the presence of extensions that are optional in this base
      profile, defining new optional or critical extension types, or
      restricting the values and/or presence of fields within existing
      extensions. However, communications between distinct communities
      MUST conform with the requirements specified in this document when
      interoperability is desired. Applications may add requirements for
      additional non-critical extensions, but they MUST NOT assume that a
      remote peer will be able to process them. */

      describe('4.1 Implementing the CNSA Suite', function() {
         let pubKey;
         before(function() {
             pubKey = crlIssuerCert.getPublicKey();
         });
         /* Every CNSA Suite certificate MUST use the X.509 v3 format and
         contain one of the following:
            o  An ECDSA-capable signature verification key using curve P-384,
               or
            o  An ECDH-capable (Elliptic Curve Diffie-Hellman) key establishment
               key using curve P-384, or
            o  An RSA-capable signature verification key using RSA-3072 or
               RSA-4096, or
            o  An RSA-capable key transport key using RSA-3072 or RSA-4096.

         The signature applied to all CNSA Suite certificates and CRLs MUST be
         made with a signing key that is either generated on the curve P-384,
         or is an RSA-3072 or RSA-4096 key. The SHA-384 hashing algorithm
         MUST be used for all certificate and CRL signatures irrespective of
         the type of key used. */
         describe('CRL issuer certificate', function() {
            it('is signed with curve P-384, RSA-3072, or RSA-4096', function() {
               // console.log(pubKey);
               if (pubKey.type === 'EC')
                   expect(pubKey.curveName).to.equal('secp384r1');
               else
                   expect(pubKey.n.bitLength()).to.be.oneOf([3072, 4096]);
            });
            it('uses SHA-384 hashing algorithm', function() {
               expect(crlIssuerCertParams.sigalg).to.match(/^SHA384with.*$/);
            });
         });
         /* The RSA exponent "e" MUST satisfy 2^16<e<2^256 and be odd per
         [FIPS186]. */
         describe('RSA exponent "e"', function() {
            before(function() {
               if (pubKey.type === 'EC')
                  this.skip();
            });
            it('satisfy 2^16<e<2^256', function() {
               const hex = pubKey.e.toString(16);
               const e = BigInt(`0x${hex}`);
               expect(e > 2n ** 16n).to.be.true;
               expect(e < 2n ** 256n).to.be.true;
            });
            it('is odd', function() {
               const hex = pubKey.e.toString(16);
               const e = BigInt(`0x${hex}`);
               expect(e % 2n).to.be.equal(1n);
            });
         });

         /* The requirements of this document are not intended to preclude use of
         RSASSA-PSS signatures.  However, Certification Authorities (CAs)
         conforming with this document will not issue certificates specifying
         that algorithm for subject public keys.  Protocols that use RSASSA-
         PSS should be configured to use certificates that specify
         rsaEncryption as the subject public key algorithm.  Protocols that
         use these keys with RSASSA-PSS signatures must use the following
         parameters: the hash algorithm (used for both mask generation and
         signature generation) must be SHA-384, the mask generation function 1
         from [RFC8017] must be used, and the salt length must be 48 octets. */
     });
     describe('4.2. CNSA Suite Object Identifiers', function() {
        describe('4.2.1. CNSA Suite Object Identifiers for ECDSA', function() {
           /* The primary Object Identifier (OID) structure for the CNSA Suite
           is as follows per [X962], [SEC2], [RFC5480], and [RFC5758].

            ansi-X9-62 OBJECT IDENTIFIER ::= {
               iso(1) member-body(2) us(840) 10045 }

            certicom-arc OBJECT IDENTIFIER ::= {
               iso(1) identified-organization(3) certicom(132) }

            id-ecPublicKey OBJECT IDENTIFIER ::= {
               ansi-X9-62 keyType(2) 1 }

            secp384r1 OBJECT IDENTIFIER ::= {
               certicom-arc curve(0) 34 }

            id-ecSigType OBJECT IDENTIFIER ::= {
               ansi-X9-62 signatures(4) }

            ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
               id-ecSigType ecdsa-with-SHA2(3) 3 } */
        });
        describe('4.2.2. CNSA Suite Object Identifiers for RSA', function() {
           /* The primary OID structure for CNSA Suite is as follows per
           [RFC3279].

            pkcs-1 OBJECT IDENTIFIER ::= {
               iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }

            rsaEncryption OBJECT IDENTIFIER ::= {
               pkcs-1 1}

           The rsaEncryption OID is intended to be used in the algorithm field
           of a value of type AlgorithmIdentifier.  The parameters field MUST
           have ASN.1 type NULL for this algorithm identifier.

           The object identifier used to identify the PKCS #1 version 1.5
           signature algorithm with SHA-384 is per [RFC4055]:

            sha384WithRSAEncryption  OBJECT IDENTIFIER  ::=  {
               pkcs-1 12 } */
       });
   });
   describe('5. CNSA Suite Base Certificate Required Values', function() {
      /* This section specifies changes to the basic requirements in [RFC5280]
      for applications that create or use CNSA Suite certificates.  Note
      that RFC 5280 has varying mandates for marking extensions as critical
      or non-critical.  This profile changes some of those mandates for
      extensions that are included in CNSA Suite certificates. */
      describe('5.1. signatureAlgorithm', function() {
         let pubKey;
         before(function() {
            pubKey = crlIssuerCert.getPublicKey();
            if (pubKey.type === 'EC')
               this.skip();
         });
         describe('5.1.1. ECDSA', function() {
            before(function() {
               if (pubKey.type !== 'EC')
                  this.skip();
            });
            /* For ECDSA, the algorithm identifier used by the CNSA Suite is as
            described in [RFC5758] and [X962]:

               1.2.840.10045.4.3.3 for ecdsa-with-SHA384 */
            it('CRL is signed with ecdsa-with-SHA384', function() {
               expect(parsed.sigalg).to.be.equal('SHA384withECDSA');
            });
            /* The parameters MUST be absent as per [RFC5758]. */
         });
         describe('5.1.2. RSA', function() {
            before(function() {
               if (pubKey.type === 'EC')
                  this.skip();
            });
            /* For RSA, the algorithm identifier used by the CNSA Suite is as
            described in [RFC4055]:

               1.2.840.113549.1.1.12 for sha384WithRSAEncryption. */
            it('CRL is signed with sha384WithRSAEncryption', function() {
               expect(parsed.sigalg).to.be.equal('SHA384withRSA');
            });
            /* Per [RFC4055], the parameters MUST be NULL.  Implementations MUST
            accept the parameters being absent as well as present. */
         });
      });
      describe('5.2. signatureValue', function() {
         describe('5.2.1. ECDSA', function() {
            before(function() {
               if (pubKey.type !== 'EC')
                  this.skip();
            });
            /* ECDSA digital signature generation is described in [FIPS186].  An
            ECDSA signature value is composed of two unsigned integers, denoted
            as "r" and "s".  "r" and "s" MUST be represented as ASN.1 INTEGERs.
            If the high-order bit of the unsigned integer is a 1, an octet with
            the value 0x00 MUST be prepended to the binary representation before
            encoding it as an ASN.1 INTEGER.  Unsigned integers for the P-384
            curves can be a maximum of 48 bytes.  Therefore, converting each "r"
            and "s" to an ASN.1 INTEGER will result in a maximum of 49 bytes for
            the P-384 curve.

            The ECDSA signatureValue in an X.509 certificate is encoded as a BIT
            STRING value of a DER-encoded SEQUENCE of the two INTEGERS. */
         });
         describe('5.2.2. RSA', function() {
            before(function() {
               if (pubKey.type === 'EC')
                  this.skip();
            });
            /* The RSA signature generation process and the encoding of the result
            is RSASSA-PKCS1-v1_5 as described in detail in PKCS #1 version 2.2
            [RFC8017]. */
         });
      });
      describe('5.3. Version', function() {
         /* For this profile, Version MUST be v3, which means the value MUST be
         set to 2. */
         describe('CRL CA certificate', function() {
            it('has version 2', function() {
               expect(crlCaCertParams.version).to.be.equal(3);
            });
         });
         describe('CRL issuer certificate', function() {
            before(function() {
               if (crlIssuerCertFile === crlCaCertFile)
                  this.skip()
            });
            it('has version 2', function() {
               expect(crlIssuerCertParams.version).to.be.equal(3);
            });
         });
      });
      describe('5.4. SubjectPublicKeyInfo', function() {
         describe('5.4.1. Elliptic Curve Cryptography', function() {
            before(function() {
               if (pubKey.type !== 'EC')
                  this.skip();
            });
            /* For ECDSA signature verification keys and ECDH key agreement keys,
            the algorithm ID id-ecPublicKey MUST be used.

            The parameters of the AlgorithmIdentifier in this field MUST use the
            namedCurve option.  The specifiedCurve and implicitCurve options
            described in [RFC5480] MUST NOT be used.  The namedCurve MUST be the
            OID for secp384r1 (curve P-384) [RFC5480].

            The elliptic curve public key, ECPoint, SHALL be the OCTET STRING
            representation of an elliptic curve point following the conversion
            routine in Section 2.2 of [RFC5480] and Sections 2.3.1 and 2.3.2 of
            [SEC1].

            CNSA Suite implementations MAY use either the uncompressed form or
            the compressed form of the elliptic curve point [RFC5480].  For
            interoperability purposes, all relying parties MUST be prepared to
            process the uncompressed form.

            The elliptic curve public key (an ECPoint that is an OCTET STRING) is
            mapped to a subjectPublicKey (a BIT STRING) as follows: the most
            significant bit of the OCTET STRING becomes the most significant bit
            of the BIT STRING, and the least significant bit of the OCTET STRING
            becomes the least significant bit of the BIT STRING [RFC5480]. */
         });
         describe('5.4.2. RSA', function() {
            before(function() {
               if (pubKey.type === 'EC')
                  this.skip();
            });
            /* For RSA signature verification keys and key transport keys, the
            algorithm ID, rsaEncryption, MUST be used.

            The parameters field MUST have ASN.1 type NULL for this algorithm
            identifier [RFC3279].

            The RSA public key MUST be encoded using the ASN.1 type RSAPublicKey
            per Section 2.3.1 of [RFC3279]. */
         });
      });
   });
   describe('6. Certificate Extensions for Particular Types of Certificates', function() {
      /* Different types of certificates in this profile have different
      required and recommended extensions.  Those are listed in this
      section.  Those extensions from RFC 5280 not explicitly listed in
      this profile remain at the requirement levels of RFC 5280. */
      describe('6.1. CNSA Suite Self-Signed CA Certificates', function() {
         before(function() {
             try {
                 if (!crlIssuerCert.verifySignature(crlIssuerCert.getPublicKey()))
                     this.skip();
             }
             catch (error) {
                 if (/unsupported public key alg: (ecdsa|eddsa|rsa)/.test(error))
                     this.skip();
             }
         });
         /* In adherence with [RFC5280], self-signed CA certificates in this
         profile MUST contain the subjectKeyIdentifier, keyUsage, and
         basicConstraints extensions. */
         describe('CRL CA certificate', function() {
            it('has subjectKeyIdentifier', function() {
               expect(crlCaCertParams.ext.some((ext) => ext.extname === 'subjectKeyIdentifier')).to.be.true;
            });
            it('has keyUsage', function() {
               expect(crlCaCertParams.ext.some((ext) => ext.extname === 'keyUsage')).to.be.true;
            });
            it('has basicConstraints', function() {
               expect(crlCaCertParams.ext.some((ext) => ext.extname === 'basicConstraints')).to.be.true;
            });

            /* The keyUsage extension MUST be marked as critical.  The keyCertSign
            and cRLSign bits MUST be set.  The digitalSignature and
            nonRepudiation bits MAY be set.  All other bits MUST NOT be set. */
            it('has keyUsage extension marked critical', function() {
               let keyUsage = crlCaCertParams.ext.find((ext) => ext.extname == 'keyUsage');
               expect(keyUsage).not.to.be.undefined;
               expect(keyUsage).to.have.own.property('critical');
               expect(keyUsage.critical).to.be.true;
            });
            it('keyUsage keyCertSign and CRLsign set', function() {
               let keyUsage = crlCaCertParams.ext.find((ext) => ext.extname == 'keyUsage');
               expect(keyUsage).not.to.be.undefined;
               expect(keyUsage.names).to.include.members(['cRLSign', 'keyCertSign']);
            });
            it('keyUsage does not have other bits set', function() {
               let keyUsage = crlCaCertParams.ext.find((ext) => ext.extname == 'keyUsage');
               expect(keyUsage).not.to.be.undefined;
               expect(['cRLSign', 'keyCertSign', 'digitalSignature', 'nonRepudiation']).to.include.members(keyUsage.names);
            });
            /* In adherence with [RFC5280], the basicConstraints extension MUST be
            marked as critical.  The cA boolean MUST be set to indicate that the
            subject is a CA, and the pathLenConstraint MUST NOT be present. */
            it('has basicConstraints marked critical', function() {
               let basicConstraints = crlCaCertParams.ext.find((ext) => ext.extname == 'basicConstraints');
               expect(basicConstraints).not.to.be.undefined;
               expect(basicConstraints).to.have.own.property('critical');
               expect(basicConstraints.critical).to.be.true;
            });
            it('has basicConstraints has cA true', function() {
               let basicConstraints = crlCaCertParams.ext.find((ext) => ext.extname == 'basicConstraints');
               expect(basicConstraints).not.to.be.undefined;
               expect(basicConstraints).to.have.own.property('cA');
               expect(basicConstraints.cA).to.be.true;
            });
            it('has basicConstraints without pathlen', function() {
               let basicConstraints = crlCaCertParams.ext.find((ext) => ext.extname == 'basicConstraints');
               expect(basicConstraints).not.to.be.undefined;
               expect(basicConstraints).not.to.have.own.property('pathLen');
            });
         });
      });
      describe('6.2. CNSA Suite Non-Self-Signed CA Certificates', function() {
         before(function() {
             try {
                 if (crlIssuerCert.verifySignature(crlIssuerCert.getPublicKey()))
                     this.skip();
             }
             catch (error) {
                 if (!/unsupported public key alg: (ecdsa|eddsa|rsa)/.test(error))
                     this.skip();
             }
         });
         describe('CRL issuer certificate', function() {
            /* Non-self-signed CA Certificates in this profile MUST contain the
            authorityKeyIdentifier, keyUsage, and basicConstraints extensions. */
            it('has authorityKeyIdentifier', function() {
               expect(crlIssuerCertParams.ext.some((ext) => ext.extname === 'authorityKeyIdentifier')).to.be.true;
            });
            it('has keyUsage', function() {
               expect(crlIssuerCertParams.ext.some((ext) => ext.extname === 'keyUsage')).to.be.true;
            });
            it('has basicConstraints', function() {
               expect(crlIssuerCertParams.ext.some((ext) => ext.extname === 'basicConstraints')).to.be.true;
            });

            /* If there is a policy to be asserted, then the certificatePolicies
            extension MUST be included. */
            /* The keyUsage extension MUST be marked as critical. The keyCertSign
            and CRLSign bits MUST be set. The digitalSignature and
            nonRepudiation bits MAY be set. All other bits MUST NOT be set. */
            it('has keyUsage extension marked critical', function() {
               let keyUsage = crlIssuerCertParams.ext.find((ext) => ext.extname == 'keyUsage');
               expect(keyUsage).not.to.be.undefined;
               expect(keyUsage).to.have.own.property('critical');
               expect(keyUsage.critical).to.be.true;
            });
            it('keyUsage keyCertSign and CRLsign set', function() {
               let keyUsage = crlIssuerCertParams.ext.find((ext) => ext.extname == 'keyUsage');
               expect(keyUsage).not.to.be.undefined;
               expect(keyUsage.names).to.include.members(['cRLSign', 'keyCertSign']);
            });
            it('keyUsage does not have ', function() {
               let keyUsage = crlIssuerCertParams.ext.find((ext) => ext.extname == 'keyUsage');
               expect(keyUsage).not.to.be.undefined;
               expect(['cRLSign', 'keyCertSign', 'digitalSignature', 'nonRepudiation']).to.include.members(keyUsage.names);
            });

            /* In adherence with [RFC5280], the basicConstraints extension MUST be
            marked as critical. The cA boolean MUST be set to indicate that the
            subject is a CA, and the pathLenConstraint subfield is OPTIONAL. */
            it('has basicConstraints marked critical', function() {
               let basicConstraints = crlIssuerCertParams.ext.find((ext) => ext.extname == 'basicConstraints');
               expect(basicConstraints).not.to.be.undefined;
               expect(basicConstraints).to.have.own.property('critical');
               expect(basicConstraints.critical).to.be.true;
            });
            it('has basicConstraints has cA true', function() {
               let basicConstraints = crlIssuerCertParams.ext.find((ext) => ext.extname == 'basicConstraints');
               expect(basicConstraints).not.to.be.undefined;
               expect(basicConstraints).to.have.own.property('cA');
               expect(basicConstraints.cA).to.be.true;
            });
            /* If a policy is asserted, the certificatePolicies extension MUST be
            marked as non-critical, MUST contain the OIDs for the applicable
            certificate policies, and SHOULD NOT use the policyQualifiers option.
            If a policy is not asserted, the certificatePolicies extension MUST
            be omitted.

            Relying party applications conforming to this profile MUST be
            prepared to process the policyMappings, policyConstraints, and
            inhibitAnyPolicy extensions, regardless of criticality, following the
            guidance in [RFC5280] when they appear in non-self-signed CA
            certificates. */
         });
      });
      describe('6.3. CNSA Suite End-Entity Signature and Key Establishment Certificates', function() {
         /* In adherence with [RFC5280], end-entity certificates in this profile
         MUST contain the authorityKeyIdentifier and keyUsage extensions.  If
         there is a policy to be asserted, then the certificatePolicies
         extension MUST be included.  End-entity certificates SHOULD contain
         the subjectKeyIdentifier extension.

         The keyUsage extension MUST be marked as critical.

         For end-entity digital signature certificates, the keyUsage extension
         MUST be set for digitalSignature.  The nonRepudiation bit MAY be set.
         All other bits in the keyUsage extension MUST NOT be set.

         For end-entity key establishment certificates, in ECDH certificates,
         the keyUsage extension MUST be set for keyAgreement; in RSA
         certificates, the keyUsage extension MUST be set for keyEncipherment.
         The encipherOnly or decipherOnly bit MAY be set.  All other bits in
         the keyUsage extension MUST NOT be set.

         If a policy is asserted, the certificatePolicies extension MUST be
         marked as non-critical, MUST contain the OIDs for the applicable
         certificate policies, and SHOULD NOT use the policyQualifiers option.
         If a policy is not asserted, the certificatePolicies extension MUST
         be omitted. */
      });
   });
   describe('7. CNSA Suite CRL Requirements', function() {
      /* This CNSA Suite CRL profile is a profile of [RFC5280].  There are
      changes in the requirements from [RFC5280] for the signatures on CRLs
      of this profile. */
      it('is signed with curve P-384, RSA-3072, or RSA-4096', function() {
         expect(parsed.sigalg).to.be.oneOf(['SHA384withECDSA', 'SHA384withRSA', 'SHA384withRSAandMGF1']);
      });
      it('uses SHA-384 hashing algorithm', function() {
         expect(parsed.sigalg).to.match(/^SHA384with.*$/);
      });
      /* The signatures on CRLs in this profile MUST follow the same rules
      from this profile that apply to signatures in the certificates.  See
      Section 4. */
   });
   describe('8. Security Considerations', function() {
      /* The security considerations in [RFC3279], [RFC4055], [RFC5280],
      [RFC5480], [RFC5758], and [RFC8017] apply.

      A single key pair SHOULD NOT be used for both signature and key
      establishment per [SP80057]. */
   });
});
});
