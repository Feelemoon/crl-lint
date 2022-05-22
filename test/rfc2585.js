const fs = require('node:fs');
const assert = require('node:assert');

const chai = require('chai');
const expect = chai.expect;

const jsrsasign = require('jsrsasign');

const crlFile = process.env.CRL_FILE || 'test.crl';

describe('RFC2585', function() {
   let der;

   before(function() {
      return fs.readFile(crlFile, (err, buf) => {
         assert.equal(err, undefined);
         der = buf;
      });
   });
   describe('2  FTP Conventions', function() {
      /* Within certificate extensions and CRL extensions, the URI form of
      GeneralName is used to specify the location where issuer certificates
      and CRLs may be obtained.  For instance, a URI identifying the
      subject of a certificate may be carried in subjectAltName certificate
      extension. An IA5String describes the use of anonymous FTP to fetch
      certificate or CRL information.  For example:

         ftp://ftp.netcom.com/sp/spyrus/housley.cer
         ftp://ftp.your.org/pki/id48.cer
         ftp://ftp.your.org/pki/id48.no42.crl

      Internet users may publish the URI reference to a file that contains
      their certificate on their business card.  This practice is useful
      when there is no Directory entry for that user.  FTP is widely
      deployed, and anonymous FTP are accommodated by many firewalls.
      Thus, FTP is an attractive alternative to Directory access protocols
      for certificate and CRL distribution.  While this service satisfies
      the requirement to retrieve information related to a certificate
      which is already identified by a URI, it is not intended to satisfy
      the more general problem of finding a certificate for a user about
      whom some other information, such as their electronic mail address or
      corporate affiliation, is known.

      For convenience, the names of files that contain certificates should
      have a suffix of ".cer".  Each ".cer" file contains exactly one
      certificate, encoded in DER format.  Likewise, the names of files
      that contain CRLs should have a suffix of ".crl".  Each ".crl" file
      contains exactly one CRL, encoded in DER format. */
      it('has a suffix of .crl', function() {
         expect(crlFile.endsWith('.crl')).to.be.true;
      });
      it('is encoded in DER format', function() {
         let hex = Buffer.from(der, 'binary').toString('hex');
         expect(jsrsasign.ASN1HEX.isASN1HEX(hex)).to.be.true;
      });
   });
   describe('3. HTTP Conventions', function() {
      /* Within certificate extensions and CRL extensions, the URI form of
      GeneralName is used to specify the location where issuer certificates
      and CRLs may be obtained.  For instance, a URI identifying the
      subject of a certificate may be carried in subjectAltName certificate
      extension. An IA5String describes the use of HTTP to fetch
      certificate or CRL information.  For example:

         http://www.netcom.com/sp/spyrus/housley.cer
         http://www.your.org/pki/id48.cer
         http://www.your.org/pki/id48.no42.crl

      Internet users may publish the URI reference to a file that contains
      their certificate on their business card.  This practice is useful
      when there is no Directory entry for that user.  HTTP is widely
      deployed, and HTTP is accommodated by many firewalls.  Thus, HTTP is
      an attractive alternative to Directory access protocols for
      certificate and CRL distribution.  While this service satisfies the
      requirement to retrieve information related to a certificate which is
      already identified by a URI, it is not intended to satisfy the more
      general problem of finding a certificate for a user about whom some
      other information, such as their electronic mail address or corporate
      affiliation, is known.

      For convenience, the names of files that contain certificates should
      have a suffix of ".cer".  Each ".cer" file contains exactly one
      certificate, encoded in DER format.  Likewise, the names of files
      that contain CRLs should have a suffix of ".crl".  Each ".crl" file
      contains exactly one CRL, encoded in DER format. */

      it('has a suffix of .crl', function() {
         expect(crlFile.endsWith('.crl')).to.be.true;
      });
      it('is encoded in DER format', function() {
         let hex = Buffer.from(der, 'binary').toString('hex');
         expect(jsrsasign.ASN1HEX.isASN1HEX(hex)).to.be.true;
      });
   });
});
