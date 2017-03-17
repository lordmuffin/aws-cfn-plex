# (c) 2015, Ensighten <infra@ensighten.com>
# Modified by Paul Miller <paul.miller@entrust.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible import constants as C
from Crypto.PublicKey import RSA
from OpenSSL import crypto, SSL
from uuid import uuid4 as random_uuid
import base64
import os
import time

CREDSTASH_INSTALLED = False
DEFAULT_LENGTH = 40
DEFAULT_KEYLENGTH = 4096
PAD_LEN = 19 # number of digits in sys.maxint

try:
    import credstash
    CREDSTASH_INSTALLED = True
except ImportError:
    CREDSTASH_INSTALLED = False

class LookupModule(LookupBase):
    def random_uuid(self):
        '''
        Use the Python uuid4 to generate a 'truly random' uuid - useful in creating Consul ACL tokens
        '''
        key = random_uuid()
        return str(key)

    def random_rsa(self, keylength=DEFAULT_KEYLENGTH):
        '''
        Return a random RSA (public, private) keypair with a key length of DEFAULT_KEYLENGTH.
        '''

        key = RSA.generate(keylength, os.urandom)
        pubkey = key.publickey()

        return (key.exportKey('PEM'), pubkey.exportKey('OpenSSH'))

    def random_password(self, length=DEFAULT_LENGTH, chars=C.DEFAULT_PASSWORD_CHARS):
        '''
        Return a random password string of length containing only chars.
        NOTE: this was copied from the Ansible 'password' module.
        '''

        password = []
        while len(password) < length:
            new_char = os.urandom(1)
            if new_char in chars:
                password.append(new_char)

        return ''.join(password)

    # Credstash CA Helper Functions
    def create_key_pair(self, bits=4096, type=crypto.TYPE_RSA):
        """
        Create a key pair for use in PKI
        Arguments: bits   - the number of bits to use in the private key
                   type   - the type of key (currently only crypto.TYPE_RSA supported)
        """

        if bits % 1024 != 0 or bits < 2048 != 0:
            raise ValueError("This implementation requires a key size evenly divisible by 1024 and larger than 2048.")

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, bits)
        return k

    def create_certificate_request(self, pkey, digest='sha256', **name):
        """
        Create a certificate request.
        Arguments: key        - The key to associate with the request
                   digest     - Digestion method to use for signing, default is sha256
                   **name     - The name of the subject of the request, possible
                                arguments are:
                                 C     - Country name
                                 ST    - State or province name
                                 L     - Locality name
                                 O     - Organization name
                                 OU    - Organizational unit name
                                 CN    - Common name
                                 emailAddress - E-mail address
        Returns:   The certificate request in an X509Req object
        """

        request = crypto.X509Req()
        subject = request.get_subject()

        # Handle creating the subject of the request
        for(key,value) in name.items():
            setattr(subject, key, value)

        request.set_pubkey(pkey)

        # Sign the request
        request.sign(pkey, digest)
        return request

    def create_certificate(self, request, issuer_cert, issuer_key, serial, days=3650, digest='sha256', extensions=[], subject_alt_names='', version=2):
        """
        Generate a certificate given the certificate request.

        Arguments: request     - Certificate request to sign
                   issuer_cert - The certificate of the issuer
                   issuer_key  - The private key of the issuer
                   extensions        - x509 extensions provided as a dictionary :name, :critical, :value
                   subject_alt_names - subject alt names e.g. IP:192.168.7.1 or DNS:my.domain
                   serial      - The serial number to assign to the certificate
                   days        - The number of days of validity (starting from now)
                   digest      - The digest method for signing (by default sha256)
        """

        certificate = crypto.X509()

        # Handle x509 extensions
        for extension in extensions:
            # handle issuer and subjects that need to be self-referential (root certificate)
            if 'subject' in extension.keys() and extension['subject'] == 'self':
                extension['subject'] = certificate
            if 'issuer' in extension.keys() and extension['issuer'] == 'self':
                extension['issuer'] = certificate
            elif 'issuer' in extension.keys() and extension['issuer'] != 'self':
                extension['issuer'] = issuer_cert

            # have to explicitly set 'critical' extension to a bool.
            if 'critical' in extension.keys():
                extension['critical'] = extension['critical'].lower() in ("yes", "true", "t", "1")

            # add the extensions to the request
            certificate.add_extensions([crypto.X509Extension(**extension)])

        # Handle the subject alternative names (these are just X509 extensions)
        if len(subject_alt_names) != 0:
            certificate.add_extensions([crypto.X509Extension("subjectAltName", False, ", ".join(subject_alt_names))])

        certificate.set_serial_number(serial)
        certificate.set_version(version)
        certificate.gmtime_adj_notBefore(0)
        certificate.gmtime_adj_notAfter(days*86400)
        certificate.set_subject(request.get_subject())
        certificate.set_issuer(issuer_cert.get_subject())
        certificate.set_pubkey(request.get_pubkey())
        certificate.sign(issuer_key, digest)
        return certificate

    def paddedInt(self,i):
        '''
        return a string that contains `i`, left-padded with 0's up to PAD_LEN digits
        '''
        i_str = str(i)
        pad = PAD_LEN - len(i_str)
        return (pad * "0") + i_str

    # The Lookup Plugin Implementation Begins Here:
    def run(self, terms, variables, **kwargs):

        if not CREDSTASH_INSTALLED:
            raise AnsibleError('The credstash lookup plugin requires credstash to be installed.')

        ret = []
        for term in terms:
            version = kwargs.pop('version', '')
            region = kwargs.pop('region', None)
            table = kwargs.pop('table', 'credential-store')
            kms_alias = kwargs.pop('kms_alias', 'alias/credstash')
            keytype = kwargs.pop('keytype', 'password')
            secret = kwargs.pop('secret', None)
            digest = kwargs.pop('digest', 'SHA512')
            context = kwargs.pop('context', None)
            cert_request = kwargs.pop('cert_request', None)
            transient = kwargs.pop('transient', False) # if transient we don't save certificates

            # Deal with credstash version numbers...
            if version == '':
                version = self.paddedInt(1)
            else:
                version = self.paddedInt(version)

            if 'alias/' not in kms_alias:
                kms_alias = 'alias/{0}'.format(kms_alias)

            try:
                if keytype == 'password' or keytype == 'manual' or keytype == 'consul-gossip-encryption-key' or keytype == 'uuid':
                    val = credstash.getSecret(term, version, region, table, context=context)
                elif keytype == 'ssh-key':
                    id_rsa = credstash.getSecret(term+'_private', version, region, table, context=context)
                    id_rsa_pub = credstash.getSecret(term+'_public', version, region, table, context=context)
                    val = [id_rsa_pub, id_rsa]
                elif keytype == 'x509':
                    ca_ser = credstash.getSecret(term+'_serial', version, region, table, context=context)
                    ca_key = credstash.getSecret(term+'_key', version, region, table, context=context)
                    ca_csr = credstash.getSecret(term+'_csr', version, region, table, context=context)
                    ca_crt = credstash.getSecret(term+'_crt', version, region, table, context=context)
                    val = [ca_ser, ca_key, ca_csr, ca_crt]
                else:
                    raise AnsibleError('Invalid password type: {0}'.format(keytype))
            except credstash.ItemNotFound:
                if keytype == 'password':
                    secret = self.random_password()
                    rc = credstash.putSecret(name=term, secret=secret, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                    val = secret
                elif keytype == 'uuid':
                    secret = self.random_uuid()
                    rc = credstash.putSecret(name=term, secret=secret, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                    val = secret
                elif keytype == 'ssh-key':
                    (id_rsa,id_rsa_pub) = self.random_rsa()
                    rc_rsa = credstash.putSecret(name=term+'_private', secret=id_rsa, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                    rc_rsa_pub = credstash.putSecret(name=term+'_public', secret=id_rsa_pub, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                    val = [id_rsa_pub, id_rsa]
                elif keytype == 'x509':
                    # For use in creating a PKI, we can create x509 requests
                    bits = cert_request.get('bits', 4096)
                    cert_digest = cert_request.get('hash', 'sha256')
                    extensions = cert_request.get('extensions', [])
                    subject = cert_request.get('subject', { 'CN': term })
                    subject_alt_names = cert_request.get('subject_alt_names', '')
                    days = cert_request.get('days', 3650)
                    ca = cert_request.get('ca', None)
                    cert_version = int(cert_request.get('version', 1))

                    # Get the latest version of the ca_serial ca_key and ca_crt
                    if ca:
                        ca_ser = int(credstash.getSecret(ca+'_serial', '', region, table, context=context))
                        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, credstash.getSecret(ca+'_key', '', region, table, context=context))
                        ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, credstash.getSecret(ca+'_crt', '', region, table, context=context))

                    # handle any weird unicode conversion issues on subjects and extensions and subjectaltnames
                    subject = dict((str(k), str(v)) for (k,v) in subject.items())
                    extensions = [dict((str(k), str(v)) for (k, v) in i.items()) for i in extensions]
                    subject_alt_names = [str(x) for x in subject_alt_names]

                    # create the key and certificate signing request
                    key = self.create_key_pair(bits=bits)
                    csr = self.create_certificate_request(key, digest=cert_digest, **subject)

                    # if this certificate needs to be signed, the 'ca' attribute will be set to the name of the CA.
                    # use the ca_key and ca_crt to sign, and increment the serial number associated with the ca_ser.
                    if ca:
                        rc_ser = int(ca_ser) + 1
                        crt = self.create_certificate(csr, ca_crt, ca_key, int(rc_ser), days=days, digest=cert_digest, extensions=extensions, subject_alt_names=subject_alt_names, version=cert_version)
                        if not transient:
                            credstash.putSecret(name=ca+'_serial', secret=str(rc_ser), version=self.paddedInt(rc_ser), kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                    else:
                        rc_ser = "1"
                        crt = self.create_certificate(csr, csr, key, int(rc_ser), days=days, digest=cert_digest, extensions=extensions, subject_alt_names=subject_alt_names, version=cert_version)

                    # write the configuration for this x509 certificate to credstash if not transient
                    rc_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
                    rc_csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
                    rc_crt = crypto.dump_certificate(crypto.FILETYPE_PEM, crt)

                    if not transient:
                        credstash.putSecret(name=term+'_serial', secret=str(rc_ser), version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                        credstash.putSecret(name=term+'_key', secret=rc_key, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                        credstash.putSecret(name=term+'_csr', secret=rc_csr, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                        credstash.putSecret(name=term+'_crt', secret=rc_crt, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)

                    val = [rc_ser, rc_key, rc_csr, rc_crt]
                elif keytype == 'consul-gossip-encryption-key':
                    # Consul Gossip Encryption keys are 16-byte base64 encoded numbers
                    key = os.urandom(16)
                    secret = base64.b64encode(key)
                    rc = credstash.putSecret(name=term, secret=secret, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                    val = secret
                elif keytype == 'manual':
                    if secret is not None:
                        rc = credstash.putSecret(name=term, secret=secret, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                        val = secret
                    else:
                        raise AnsibleError('Key {0} is flagged as manually set, but has not yet been set'.format(term))
                else:
                    raise AnsibleError('Invalid password type: {0}'.format(keytype))
            except Exception as e:
                raise AnsibleError('Encountered exception while fetching {0}: {1}'.format(term, e.message))
            ret.append(val)

        return ret
