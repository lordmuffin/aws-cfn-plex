import json
import boto3
import cfnresponse
import urllib
from botocore.exceptions import ClientError
from Crypto.PublicKey import RSA
from OpenSSL import crypto, SSL
from uuid import uuid4 as random_uuid
import credstash
import base64
import os
import time

DEFAULT_LENGTH = 40
DEFAULT_KEYLENGTH = 4096
PAD_LEN = 19 # number of digits in sys.maxint
DEFAULT_PASSWORD_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@[\]^_{|}~"

class Credential:
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

    def random_password(self, length=DEFAULT_LENGTH, chars=DEFAULT_PASSWORD_CHARS):
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

    # Credential Deletion occurs here:
    def delete(self, **kwargs):
        secret_name = kwargs.pop('secret_name', None)
        region = kwargs.pop('region', None)
        table = kwargs.pop('table', 'credential-store')

        credstash.deleteSecrets(secret_name, region=region, table=table)
        return

    # Credential Creation occurs here:
    def create(self, **kwargs):
        secret_name = kwargs.pop('secret_name', None)
        version = kwargs.pop('version', '')
        keytype = kwargs.pop('keytype', 'password')
        region = kwargs.pop('region', None)
        table = kwargs.pop('table', 'credential-store')
        kms_alias = kwargs.pop('kms_alias', 'alias/credstash')
        digest = kwargs.pop('digest', 'SHA512')
        context = kwargs.pop('context', None)
        cert_request = kwargs.pop('cert_request', None)
        transient = kwargs.pop('transient', False) # if transient we don't save certificates

        val = None

        # Deal with credstash version numbers...
        if version == '':
            version = self.paddedInt(1)
        else:
            version = self.paddedInt(version)

        if 'alias/' not in kms_alias:
            kms_alias = 'alias/{0}'.format(kms_alias)

        try:
            if keytype == 'password' :
                secret = credstash.getSecret(secret_name, version, region, table, context=context)
                val = {"Password": secret}
            elif keytype == 'manual':
                secret = credstash.getSecret(secret_name, version, region, table, context=context)
                val = {"Manual": secret}
            elif keytype == 'consul-gossip-encryption-key':
                secret = credstash.getSecret(secret_name, version, region, table, context=context)
                val = {"ConsulGossipEncryptionKey": secret}
            elif keytype == 'uuid':
                secret = credstash.getSecret(secret_name, version, region, table, context=context)
                val = {"Uuid": secret}
            elif keytype == 'ssh-key':
                id_rsa = credstash.getSecret(secret_name+'_private', version, region, table, context=context)
                id_rsa_pub = credstash.getSecret(secret_name+'_public', version, region, table, context=context)
                val =  {"PublicKey": id_rsa_pub}
            else:
                raise Exception('Invalid password type: {0}'.format(keytype))
        except credstash.ItemNotFound:
            if keytype == 'password':
                secret = self.random_password()
                rc = credstash.putSecret(name=secret_name, secret=secret, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                val = {"Password": secret}
            elif keytype == 'uuid':
                secret = self.random_uuid()
                rc = credstash.putSecret(name=secret_name, secret=secret, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                val = {"Uuid": secret}
            elif keytype == 'ssh-key':
                (id_rsa,id_rsa_pub) = self.random_rsa()
                rc_rsa = credstash.putSecret(name=secret_name+'_private', secret=id_rsa, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                rc_rsa_pub = credstash.putSecret(name=secret_name+'_public', secret=id_rsa_pub, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                val = {"PublicKey": id_rsa_pub}
            elif keytype == 'consul-gossip-encryption-key':
                # Consul Gossip Encryption keys are 16-byte base64 encoded numbers
                key = os.urandom(16)
                secret = base64.b64encode(key)
                rc = credstash.putSecret(name=secret_name, secret=secret, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                val = {"ConsulGossipEncryptionKey": secret}
            elif keytype == 'manual':
                if secret is not None:
                    rc = credstash.putSecret(name=secret_name, secret=secret, version=version, kms_key=kms_alias, region=region, table=table, digest=digest, context=context)
                    val = {"Manual": secret}
                else:
                    raise Exception('Key {0} is flagged as manually set, but has not yet been set'.format(secret_name))
            else:
                raise Exception('Invalid password type: {0}'.format(keytype))
        except Exception as e:
            raise Exception('Encountered exception while fetching {0}: {1}'.format(secret_name, e.message))

        return val


def lambda_handler(event, context):
    # Try to get the properties required by the handler. Fail if initialization fails
    try:
        # If not a valid cloudformation custom resource call
        if not 'RequestType' in event or not event['ResourceProperties']:
            return

        for required_property in ["SecretName", "SecretType", "SecretVersion", "TableCredstash", "KeyAlias"]:
            if not event['ResourceProperties'][required_property]:
                print "{0} is required".format(required_property)
                cfnresponse.send(event, context, cfnresponse.FAILED, "{0} is required".format(required_property), '')
                return

        secret_name = event['ResourceProperties']['SecretName']
        secret_type = event['ResourceProperties']['SecretType']
        secret_version = event['ResourceProperties']['SecretVersion']
        table = event['ResourceProperties']['TableCredstash']
        key_alias = event['ResourceProperties']['KeyAlias']
        region = context.invoked_function_arn.split(':')[3]

        print "stack {0} requested for secret {1}, version {2} of type {3}".format(event['RequestType'], secret_name, secret_version, secret_type)
        print "using table {0} in region {1} with key alias {2}".format(table, region, key_alias)

        response_status = cfnresponse.SUCCESS
        response_data = {}
        credential = Credential()

        if event['RequestType'] == 'Create':
            try:
                secret = credential.create(version=secret_version, region=region, keytype=secret_type, secret_name=secret_name, table=table, kms_alias=key_alias, digest="SHA256")
                cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data=secret)
            except Exception as e:
                print e
                cfnresponse.send(event, context, cfnresponse.FAILED, 'Could not create.', '')
                return
        elif event['RequestType'] == 'Update':
            try:
                secret = credential.create(version=secret_version, region=region, keytype=secret_type, secret_name=secret_name, table=table, kms_alias=key_alias, digest="SHA256", response_data=secret)
                cfnresponse.send(event, context, cfnresponse.SUCCESS)
            except Exception as e:
                print e
                cfnresponse.send(event, context, cfnresponse.FAILED, 'Could not update.', '')
                return
        elif event['RequestType'] == 'Delete':
            cfnresponse.send(event, context, cfnresponse.SUCCESS)
            return
        else:
            cfnresponse.send(event, context, cfnresponse.FAILED, 'Inconsistent state', '')
            return
    except Exception as e:
        print e
        cfnresponse.send(event, context, cfnresponse.FAILED, 'Error', '')
