const fs = require('node:fs');
const assert = require('node:assert');

const chai = require('chai');
chai.use(require('chai-datetime'));
chai.use(require('chai-match'));
const expect = chai.expect;

const jsrsasign = require('jsrsasign');

describe('CAB BR 1.7.3', function() {

   let crlFile = process.env.CRL_FILE || 'test.crl';
   let crlIssuerCert = process.env.CRL_ISSUER_CERT || 'test.ca.crt.pem';
   let crlCaCert = process.env.CRL_CA_CERT || crlIssuerCert;

   let raw;
   let der;
   let pem;
   let crl;
   let parsed;

   before(function(done) {
      return fs.readFile(crlFile, (err, buf) => {
         assert.equal(err, undefined);
         raw = buf;
         done();	       
      });
   });
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

   describe('7.2 CRL Profile', function() {
      it('can be parsed', function() {
         if (der === undefined) {
            this.skip();
         }
         else {
            crl = new jsrsasign.X509CRL(der.toString('hex'));
            // console.log(`crl: ${JSON.stringify(crl.getParam(), null, 4)}`);
            parsed = crl.getParam();
         }
      });

      describe('7.2.1 Version number(s)', function() {
      });

      describe('7.2.2 CRL and CRL entry extensions', function() {
         describe('1. reasonCode (OID 2.5.29.11)', function() {
            /* Effective 2020-09-30, all of the following requirements MUST be met:

            If present, this extension MUST NOT be marked critical. */
            it('is not critical', function() {
               if (!parsed.revcert) {
                  this.skip();
               }
               else {
                  let found = false;
                  for (let cert of parsed.revcert) {
                     if (cert.ext) {
                        for (let ext of cert.ext) {
                            found = true;
                            if (ext.extname === 'cRLReason')
                               expect(ext.critical).not.to.be.true;
                      }
                    }
                  }
                  if (!found)
                     this.skip();
               }
            });

            /* If a CRL entry is for a Root CA or Subordinate CA Certificate,
            including Cross Certificates, this CRL entry extension MUST be
            present. */

            /* If a CRL entry is for a Certificate not technically capable of
            causing issuance, this CRL entry extension SHOULD be present, but
            MAY be omitted, subject to the following requirements.

            The CRLReasonindicated MUST NOT be unspecified (0). If the reason
            for revocation is unspecified, CAs MUST omit reasonCode entry
            extension, if allowed by the previous requirements. */
            it('is not unspecified', function() {
               if (parsed.revcert) {
                  let withReasons = parsed.revcert.filter(cert => cert.ext);
                  for (let cert of withReasons) {
                     let reason = cert.ext.find(ext => ext.extname === 'cRLReason' && ext.code === 0);
                     expect(reason).to.be.undefined;
                  }
               }
               else {
                  this.skip();
               }
            });
 
            /* If a CRL entry is for a Certificate not subject to these
            Requirements and was either issued on-or-after 2020-09-30 or has a
            notBefore on-or-after 2020-09-30, the CRLReason MUST NOT be
            certificateHold (6). */
            it('is not certificateHold', function() {
               if (parsed.revcert) {
                  let withReasons = parsed.revcert.filter(cert => cert.ext);
                  for (let cert of withReasons) {
                     let reason = cert.ext.find(ext => ext.extname === 'cRLReason' && ext.code === 6);
                     expect(reason).to.be.undefined;
                  }
               }
               else {
                  this.skip();
               }
            });
 
            /* If a CRL entry is for a Certificate subject to these
            Requirements, the CRLReason MUST NOT be certificateHold (6). */

            /* If a reasonCode CRL entry extension is present, the CRLReason MUST
            indicate the most appropriate reason for revocation of the
            certificate, as defined by the CA within its CP/CPS. */
         });
      });
   });
});
