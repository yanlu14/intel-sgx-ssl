#Getting started with the tls_enclave example

In the scenario where a user already has a certificate and private on the host side, the tls_enclve provides an example how to protect the private key and how to estabilish a TLS connection with enclave in Linux SGX environment. 

1.  To run tls_server, the certificate and key used by the TLS server needs to be generated, the following example generate signed certificate only for testing.
(1) generate RSA key:
    openssl genrsa -f4 -aes256 -out server.key 3072
    follow the screen instructions to enter the pass phrase for protecting private key, the pass phrase should meet certain complexity requirements.
(2) generate self-signed certificate
    openssl req -new -x509 -days 365 -key server.key -out server.pem -sha256 -subj "/C=CN/ST=GD/L=SZ/O=test/OU=test/CN=test"
2. start tls_server, ./tls_server 9090 server.pem server.key &
   start tls_client, ./tls_client 9090 server.pem
   follow the screen instructions to enter the pass phrase to usee the private key. 
   After exectued successfully, the private key is deleted and only the key encrypted by enclave is saved.
