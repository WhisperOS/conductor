#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "conductor.h"
#include "config_file.h"


int TYPE_ca           = 0x0001;
int TYPE_intermediate = 0x0010;
int TYPE_server       = 0x0100;
int TYPE_client       = 0x1000;

config_t *conf;


static void seed_entropy(void);
static void cleanup_crypto(void);
static void initialize_crypto(void);
static int generate_key_csr(EVP_PKEY **key, X509_REQ **req, char *CN);
static int generate_set_random_serial(X509 *crt);
static int generate_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt, int CERT_TYPE, char *CN, int num_ips, char **ips, int num_domains, char **domains);
static int load_pair(char *key_path, EVP_PKEY **key, char *crt_path, X509 **crt);
static int save_key(const char *key_path, EVP_PKEY **key);
static int save_cert(const char *crt_path, X509 **crt, X509 **in, X509 **ca);
static int add_ext(X509V3_CTX *ctx, X509 *crt, int nid, char *value);
static char * strdup(const char *src);

int main(int argc, char *argv[])
{

#define _GNU_SOURCE
	struct option long_opts[] = {
		{ "file",   required_argument, NULL, 'f' },
		{ "help",   no_argument,       NULL, 'h' },
		{ "ip",     required_argument, NULL, 'i' },
		{ "domain", required_argument, NULL, 'd' },
		{ 0, 0, 0, 0 },
	};
	char  **ips;
	char  **domains;
	int    ip_num     = 0;
	int    domain_num = 0;
	ips     = malloc(sizeof(char *) * 20);
	domains = malloc(sizeof(char *) * 20);
	for (;;) {
		int idx = 1;
		int c = getopt_long(argc, argv, "f:h?i:+d:+", long_opts, &idx);
		if (c == -1) break;

		switch (c) {
		case 'f':
			// do nothing
		case 'h':
		case '?':
			printf("%s v%s\n\n", "conductor", VERSION);
			printf("Usage:\n"
			       "  %s [-h?] [-d domain] [-i ipaddress]  user|server|both  CN|address|email\n\n",
			       "conductor"); // BINARY

			printf("Options:\n");
			printf("  -?, -h, --help    show this help screen\n");
			printf("  -i, --ip          <IP ADDRESS>\n"
				   "                      Add a SAN IP, optional, and can be called multiple times\n");
			printf("  -d, --domain      <DOMAIN NAME>\n"
				   "                      Add a SAN domain, optional, and can be called multiple times\n");
			printf("\n");

			printf("See also:\n  %s\n", PACKAGE_URL);

			exit(EXIT_SUCCESS);

		case 'd':
			domains[domain_num] = strdup(optarg);
			domain_num++;
			break;
		case 'i':
			ips[ip_num] = strdup(optarg);
			ip_num++;
			break;
		default:
			break;
		}
	}
#undef _GNU_SOURCE
	initialize_crypto();

	conf  = malloc(sizeof(config_t));
	char *home = getenv("HOME");
	//char *etc  = "/etc/conductor.conf";
	strcat(home, "/.cndtrc");
	conductor_defaults(conf);
	// if (parse_config_file(conf, etc) != 0)  printf("crud?\n");
	if (parse_config_file(conf, home) != 0) printf("crud?\n");

	EVP_PKEY *in_key = NULL;
	X509     *in_crt = NULL;
	char *REQ_DN_CA;
	REQ_DN_CA = malloc(strlen(conf->org.o) + 24);
	strcpy(REQ_DN_CA, conf->org.o);
	strcat(REQ_DN_CA, " Root CA");
	char *REQ_DN_IN;
	REQ_DN_IN = malloc(strlen(conf->org.o) + 24);
	strcpy(REQ_DN_IN, conf->org.o);
	strcat(REQ_DN_IN, " Intermediate CA");
	X509     *ca_crt = NULL;

	if (access("intermediate_cert.pem", F_OK) != -1) {
		if (load_pair("intermediate_key.pem", &in_key, "intermediate_cert.pem", &in_crt)) {
			fprintf(stderr, "Intermediate CA detected but unable to load pair.\n");
			return 1;
		}
		if (load_pair(NULL, NULL, "ca_cert.pem", &ca_crt)) {
			fprintf(stderr, "CA detected but unable to load pair.\n");
			return 1;
		}
	} else {
		EVP_PKEY *ca_key = NULL;
		if (access("ca_cert.pem", F_OK) != -1) {
			if (load_pair("ca_key.pem", &ca_key, "ca_cert.pem", &ca_crt)) {
				fprintf(stderr, "failed to load ca pair\n");
				return 1;
			}
		} else {
			if (generate_pair(NULL, NULL, &ca_key, &ca_crt, TYPE_ca, REQ_DN_CA, 0, NULL, 0, NULL)) {
				fprintf(stderr, "Failed to generate CA keys\n");
				return 1;
			}
			save_key("ca_key.pem", &ca_key);
			save_cert("ca_cert.pem", &ca_crt, NULL, NULL);
		}
		if (generate_pair(ca_key, ca_crt, &in_key, &in_crt, TYPE_intermediate, REQ_DN_IN, 0, NULL, 0, NULL)) {
			fprintf(stderr, "Failed to generate key pair!\n");
			return 1;
		}
		save_key("intermediate_key.pem", &in_key);
		save_cert("ca_chain.pem", &in_crt, &ca_crt, NULL);
		save_cert("intermediate_cert.pem", &in_crt, NULL, NULL);
		EVP_PKEY_free(ca_key);
	}

	EVP_PKEY *key = NULL;
	X509     *crt = NULL;
	char *CN;

	if (argv[optind] != NULL && argv[optind + 1] != NULL) {
		CN = strdup(argv[optind + 1]);
		if (strncmp("both", argv[optind], 4) == 0) {
			if (generate_pair(in_key, in_crt, &key, &crt, TYPE_client|TYPE_server, CN, ip_num, ips, domain_num, domains)) {
				fprintf(stderr, "Failed to generate server key pair!\n");
				return 1;
			}
		} else if (strncmp("user", argv[optind], 4) == 0) {
			if (generate_pair(in_key, in_crt, &key, &crt, TYPE_client, CN, ip_num, ips, domain_num, domains)) {
				fprintf(stderr, "Failed to generate client key pair!\n");
				return 1;
			}
		} else if (strncmp("server", argv[optind], 6) == 0) {
			if (generate_pair(in_key, in_crt, &key, &crt, TYPE_server, CN, ip_num, ips, domain_num, domains)) {
				fprintf(stderr, "Failed to generate server key pair!\n");
				return 1;
			}
		} else {
			printf("please provide a method [user,server,both] and a CN name (user@domain.tld, server.domain.tld)\n");
			return 1;
		}
	}
	char key_path[80];
	char cert_path[80];
	char fullchain[80];
	strcpy(key_path,  CN);
	strcpy(cert_path, CN);
	strcat(key_path, ".key.pem");
	strcat(cert_path, ".cert.pem");
	strcpy(fullchain, CN);
	strcat(fullchain, ".fullchain.pem");

	save_cert(cert_path, &crt, NULL, NULL);
	save_cert(fullchain, &crt, &in_crt, &ca_crt);
	save_key(key_path, &key);

	X509_free(in_crt);
	X509_free(ca_crt);
	EVP_PKEY_free(in_key);
	X509_free(crt);
	EVP_PKEY_free(key);

	cleanup_crypto();

	return 0;
}

void seed_entropy(void) /* {{{ */
{
	char buf[40960];
	int fd = open("/dev/random", O_RDONLY);
	int n = read(fd, buf, sizeof buf);
	close(fd);
	RAND_add(buf, sizeof buf, n);
}
/* }}} */

static char * strdup(const char *src) /* {{{ */
{
	size_t len = strlen(src) + 1;
	char *s = malloc(len);
	if (s == NULL)
		return NULL;
	return (char *)memcpy(s, src, len);
}
/* }}} */

void initialize_crypto() /* {{{ */
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	CRYPTO_malloc_debug_init();
	CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
}
/* }}} */

void cleanup_crypto() /* {{{ */
{
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
	CRYPTO_mem_leaks_fp(stderr);
}
/* }}} */

int save_key(const char *key_path, EVP_PKEY **key) /* {{{ */
{
	BIO *bio = BIO_new_file(key_path, "w");
	if (!PEM_write_bio_PrivateKey(bio, *key, NULL, NULL, 0, NULL, NULL)) goto err;
	BIO_free_all(bio);
	chmod(key_path, S_IRUSR|S_IWUSR);
	BIO_free_all(bio);
	return 0;
err:
	return 1;
}
/* }}} */

int save_cert(const char *crt_path, X509 **crt, X509 **in, X509 **ca) /* {{{ */
{
	BIO *bio = BIO_new_file(crt_path, "w");
	if (crt != NULL) if (!PEM_write_bio_X509(bio, *crt)) goto err;
	if (in  != NULL) if (!PEM_write_bio_X509(bio, *in )) goto err;
	if (ca  != NULL) if (!PEM_write_bio_X509(bio, *ca )) goto err;
	BIO_free_all(bio);
	chmod(crt_path, S_IRUSR|S_IWUSR);
	return 0;
err:
	return 1;
}
/* }}} */

int load_pair(char *key_path, EVP_PKEY **key, char *crt_path, X509 **crt) /* {{{ */
{
	BIO *bio = NULL;
	if (crt_path != NULL) *crt = NULL;
	if (key_path != NULL) *key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (crt_path != NULL) if (!BIO_read_filename(bio, crt_path)) goto err;
	if (crt_path != NULL) *crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (crt_path != NULL) if (!*crt) goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (key_path != NULL) if (!BIO_read_filename(bio, key_path)) goto err;
	if (key_path != NULL) *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (key_path != NULL) if (!key) goto err;
	BIO_free_all(bio);
	return 0;
err:
	BIO_free_all(bio);
	X509_free(*crt);
	EVP_PKEY_free(*key);
	return 1;
}
/* }}} */

int add_ext(X509V3_CTX *ctx, X509 *crt, int nid, char *value) /* {{{ */
{
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value);
	if (!ex) return 1;
	X509_add_ext(crt, ex, -1);
	X509_EXTENSION_free(ex);
	return 0;
}
/* }}} */

int generate_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt, int CERT_TYPE, char *CN, int num_ips, char **ips, int num_domains, char **domains) /* {{{ */
{
	X509_REQ *req = NULL;
	if (generate_key_csr(key, &req, CN)) {
		fprintf(stderr, "Failed to generate key and/or CSR!\n");
		return 1;
	}

	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2);

	if (generate_set_random_serial(*crt)) goto err;

	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	if (CERT_TYPE & TYPE_intermediate || CERT_TYPE & TYPE_ca)
		X509_gmtime_adj(X509_get_notAfter(*crt),  315360000L);
	if (CERT_TYPE &  TYPE_server || CERT_TYPE & TYPE_client)
		X509_gmtime_adj(X509_get_notAfter(*crt),  32400000L);

	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);
	if (CERT_TYPE & TYPE_ca)
		X509_set_issuer_name(*crt, X509_get_subject_name(*crt));
	else
		X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));


	X509V3_CTX      v3ctx;
	char *NS_COMMENT;
	NS_COMMENT = malloc(strlen(conf->org.o) + 20);
	strcpy(NS_COMMENT, conf->org.o);
	strcat(NS_COMMENT, " Certificate");

	if (CERT_TYPE & TYPE_ca)
		X509V3_set_ctx(&v3ctx, *crt, *crt, NULL, NULL, 0);
	else
		X509V3_set_ctx(&v3ctx, ca_crt, *crt, NULL, NULL, 0);
	if (add_ext(&v3ctx, *crt,
		NID_subject_key_identifier, "hash")) goto err;
	if (CERT_TYPE & TYPE_intermediate || CERT_TYPE & TYPE_ca) {
		if (add_ext(&v3ctx, *crt,
			NID_authority_key_identifier, "keyid:always")) goto err;
		if (CERT_TYPE & TYPE_ca) {
			if (add_ext(&v3ctx, *crt, NID_basic_constraints, "critical,CA:TRUE")) goto err;
		} else {
			if (add_ext(&v3ctx, *crt, NID_basic_constraints, "critical,CA:TRUE,pathlen:0")) goto err;
		}
		if (add_ext(&v3ctx, *crt,
			NID_key_usage, "critical,Digital Signature,Certificate Sign,CRL Sign")) goto err;
	} else if (CERT_TYPE & TYPE_client && CERT_TYPE & TYPE_server) {
		if (add_ext(&v3ctx, *crt,
			NID_basic_constraints, "CA:FALSE")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_netscape_cert_type, "server, client, email")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_netscape_comment, NS_COMMENT)) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_authority_key_identifier, "keyid:always,issuer:always")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_key_usage, "critical,Non Repudiation,Digital Signature,Key Encipherment")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_ext_key_usage, "clientAuth,emailProtection,serverAuth")) goto err;
		char alt[4096];
		strcpy(alt, "email:");
		strcat(alt, CN);
		strcat(alt, ",DNS.1:");
		strcat(alt, CN);
		char buf[60];
		for (int d = 0; d < num_domains; d++) {
			sprintf(buf, ",DNS.%d:%s", d + 2, domains[d]);
			strcat(alt, buf);
			memset(buf, 0, 60);
		}
		for (int i = 0; i < num_ips; i++) {
			sprintf(buf, ",IP.%d:%s", i + 1, ips[i]);
			strcat(alt, buf);
			memset(buf, 0, 60);
		}
		if (add_ext(&v3ctx, *crt,
			NID_subject_alt_name, alt)) goto err;
	} else if (CERT_TYPE & TYPE_server) {
		if (add_ext(&v3ctx, *crt,
			NID_basic_constraints, "CA:FALSE")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_netscape_cert_type, "server")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_netscape_comment, NS_COMMENT)) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_authority_key_identifier, "keyid:always,issuer:always")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_key_usage, "critical,Digital Signature,Key Encipherment")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_ext_key_usage, "serverAuth")) goto err;
		char alt[4069];
		strcpy(alt, "DNS.1:");
		strcat(alt, CN);
		char buf[60];
		for (int d = 0; d < num_domains; d++) {
			sprintf(buf, ",DNS.%d:%s", d + 2, domains[d]);
			strcat(alt, buf);
			memset(buf, 0, 60);
		}
		for (int i = 0; i < num_ips; i++) {
			sprintf(buf, ",IP.%d:%s", i + 1, ips[i]);
			strcat(alt, buf);
			memset(buf, 0, 60);
		}
		if (add_ext(&v3ctx, *crt,
			NID_subject_alt_name, alt)) goto err;
	} else if (CERT_TYPE & TYPE_client) {
		if (add_ext(&v3ctx, *crt,
			NID_basic_constraints, "CA:FALSE")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_netscape_cert_type, "client, email")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_netscape_comment, NS_COMMENT)) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_authority_key_identifier, "keyid,issuer")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_key_usage, "critical,Non Repudiation,Digital Signature,Key Encipherment")) goto err;
		if (add_ext(&v3ctx, *crt,
			NID_ext_key_usage, "clientAuth,emailProtection")) goto err;
		char alt[40];
		strcpy(alt, "email:");
		strcat(alt, CN);
		if (add_ext(&v3ctx, *crt,
			NID_subject_alt_name, alt)) goto err;
	}
	if (CERT_TYPE & TYPE_ca) {
		if (X509_sign(*crt, *key, EVP_sha384()) == 0) goto err;
	} else {
		if (X509_sign(*crt, ca_key, EVP_sha384()) == 0) goto err;
	}
	X509_REQ_free(req);
	return 0;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 1;
}
/* }}} */

int generate_key_csr(EVP_PKEY **key, X509_REQ **req, char *CN) /* {{{ */
{
	BIGNUM *bne = BN_new();
	RSA    *rsa = RSA_new();

	*key = EVP_PKEY_new();
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;

	if (BN_set_word(bne, RSA_F4) != 1)
		goto err;

	seed_entropy();
	if (RSA_generate_key_ex(rsa, RSA_KEY_BITS, bne, NULL) != 1)
		goto err;
	BN_free(bne);
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	#define addName(field, value) X509_NAME_add_entry_by_txt(name, field,  MBSTRING_ASC, (unsigned char *)value, -1, -1, 0)
	X509_NAME *name = X509_REQ_get_subject_name(*req);
	addName("C",  conf->org.c);
	addName("ST", conf->org.st);
	addName("L",  conf->org.l);
	addName("O",  conf->org.o);
	addName("OU", conf->org.ou);
	addName("CN", CN);
	#undef addName

	if (!X509_REQ_sign(*req, *key, EVP_sha384())) goto err;

	return 0;
err:
	BN_free(bne);
	RSA_free(rsa);
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	return 1;
}
/* }}} */

int generate_set_random_serial(X509 *crt) /* {{{ */
{
	/* Generates a 10 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[10];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 1;

	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 0;
}
/* }}} */
