
CA=ca_files
KEYS=key_files
CERTS=cert_files

.PHONY: ca keys certs

default: all

all: ca keys certs

ca:
	mkdir -p $(CA) 
	mkdir -p $(CERTS)
	openssl req -newkey rsa:2048 -nodes -keyout $(CA)/ca_priv_key.pem -x509 -days 365 -out $(CA)/ca_root_cert.crt -subj "/C=US/ST=New York/L=New York City/O=Columbia/OU=4180group3/CN=Group 3 CA" -sha256
	echo DECAFBAD > $(CA)/ca.db.serial
	truncate --size 0 $(CA)/ca.db.index

keys:
	mkdir -p $(KEYS)
	openssl genpkey -algorithm RSA -out $(KEYS)/client.pem -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in $(KEYS)/client.pem -out $(KEYS)/client_public.pem
	openssl genpkey -algorithm RSA -out $(KEYS)/server.pem -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in $(KEYS)/server.pem -out $(KEYS)/server_public.pem

certs:
	mkdir -p $(CERTS)
	openssl req -new -sha256 -key $(KEYS)/server.pem -out $(CERTS)/server_csr.csr -subj "/C=US/ST=New York/L=New York City/O=Columbia/OU=4180 Group 3 Server/CN=Group 3 server"
	openssl ca -config ca.conf -name server_cert -keyfile $(CA)/ca_priv_key.pem -keyform PEM -cert $(CA)/ca_root_cert.crt -in $(CERTS)/server_csr.csr -out $(CERTS)/server_cert.crt -outdir $(CERTS) -notext -batch
	cat $(CA)/ca_root_cert.crt >> $(CERTS)/server_cert.crt
	openssl req -new -sha256 -key $(KEYS)/client.pem -out $(CERTS)/client_csr.csr -subj "/C=US/ST=New York/L=New York City/O=Columbia/OU=4180 Group 3 Client/CN=Group 3 client"
	openssl ca -config ca.conf -name client_cert -keyfile $(CA)/ca_priv_key.pem -keyform PEM -cert $(CA)/ca_root_cert.crt -in $(CERTS)/client_csr.csr -out $(CERTS)/client_cert.crt -outdir $(CERTS) -notext -batch
	cat $(CA)/ca_root_cert.crt >> $(CERTS)/client_cert.crt

	rm -f $(CERTS)/*.pem $(CERTS)/*.csr

clean-certs:
	rm -rf $(CA) $(KEYS) $(CERTS)

