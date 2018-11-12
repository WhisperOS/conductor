#ifndef _CONDUCTOR_H
#define _CONDUCTOR_H

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/buffer.h>

#include <lber.h>

typedef struct {
	int     daemonize;
	int     workers;
	int     sessions;
	int     verbose;
	char   *address;
	char   *conf;
	char   *pid;
	char   *uid;
	char   *gid;
	struct {
		char *uri;
		char *dn;
		char *bind;
		char *pw;
	} ldap;
	struct {
		char *keytab;
		char *principal;
	} krb5;
	struct {
		char *st;
		char *ou;
		char *l;
		char *o;
		char *c;
	} org;
	struct {
		char *key;
		char *chain;
		char *ca;
	} certs;
	struct  sockaddr_in addr;
	struct {
		char *facility;
		char *type;
		char *level;
	} log;
} config_t;

typedef struct {
	X509     *crt;
	EVP_PKEY *key;
	char     *dn;
	char     *cn; // Common name of the cert and ldap entry
} ccert_t;

#define RSA_KEY_BITS (4096)

void conductor_defaults(config_t *conf);
int auth(config_t *conf);
#endif
