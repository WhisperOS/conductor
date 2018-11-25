#define _POSIX_C_SOURCE  200112L
#include <stdlib.h>
#include <stdio.h>
#include <ldap.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sasl/sasl.h>
#include <krb5.h>

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "conductor.h"
#include "utils.h"

#define CC_NAME "MEMORY:krb5-conductor"
#define UNUSED(x) ((x)=(x))


void conductor_defaults(config_t *conf)
{
	conf->org.o  = "Defiance Technologies Inc.";
	conf->org.c  = "US";
	conf->org.ou = "IT";
	conf->org.l  = "Buffalo";
	conf->org.st = "NY";
}

struct external_defaults {
	char *bind;
	char *pw;
};

static int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *sasl_interact)
{
	UNUSED(ld);
	UNUSED(flags);
	struct external_defaults *defs = defaults;
	sasl_interact_t *interact;

	for (interact = sasl_interact; interact->id != SASL_CB_LIST_END; interact++) {
		switch (interact->id) {
			case SASL_CB_AUTHNAME:
				interact->result = defs->bind;
				interact->len    = strlen(defs->bind);
				break;
			case SASL_CB_PASS:
				interact->result = defs->pw;
				interact->len    = strlen(defs->pw);
				break;
			case SASL_CB_USER:
			case SASL_CB_NOECHOPROMPT:
			case SASL_CB_ECHOPROMPT:
				break;
		}
	}
	return LDAP_SUCCESS;
}

static int dummy_interact(LDAP *ld, unsigned flags, void *defaults, void *sasl_interact)
{
	UNUSED(ld); UNUSED(flags); UNUSED(defaults); UNUSED(sasl_interact);
	return LDAP_SUCCESS;
}

LDAP* auth(config_t *conf)
{
	LDAP *ld;
	int rc, protocol = LDAP_VERSION3;
	if ((rc = ldap_initialize(&ld, conf->ldap.uri)) != LDAP_SUCCESS) {
		fprintf(stderr, "ldap init failure (%d) [%s]\n", rc, ldap_err2string(rc));
		return NULL;
	}
	ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);

	if (conf->krb5.principal != NULL && conf->krb5.keytab != NULL) {
		krb5_context    ctx;
		krb5_principal  me;
		krb5_keytab     kt;
		krb5_creds      creds;
		int             err = 0;
		krb5_principal  princ;
		krb5_ccache     cc;

		memset(&ctx,   0, sizeof(ctx));
		memset(&me,    0, sizeof(me));
		memset(&kt,    0, sizeof(kt));
		memset(&creds, 0, sizeof(creds));
		memset(&princ, 0, sizeof(princ));
		memset(&cc,    0, sizeof(cc));

		if ((err = krb5_init_context(&ctx)) != 0) {
			rc = 1;
			goto done;
		}

		if ((err = krb5_kt_resolve(ctx, conf->krb5.keytab, &kt)) != 0)
			goto done;
		if ((err = krb5_parse_name(ctx, conf->krb5.principal, &princ)) != 0)
			goto done;
		if ((err = krb5_get_init_creds_keytab(ctx, &creds, princ, kt, 0, NULL, NULL)) != 0)
			goto done;

		if ((err = krb5_kt_close(ctx, kt)) != 0)
			goto done;

		if ((err = krb5_cc_resolve(ctx, CC_NAME, &cc)) != 0)
			goto done;
		if ((err = krb5_cc_initialize(ctx, cc, princ)) != 0)
			goto done;
		if ((err = krb5_cc_store_cred(ctx, cc, &creds)) != 0)
			goto done;
		if ((err = krb5_cc_close(ctx, cc)) != 0)
			goto done;

		if (setenv("KRB5CCNAME", CC_NAME, 1) != 0) {
			rc = 1;
			goto done;
		}
		if ((rc = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL,
					LDAP_SASL_QUIET, dummy_interact, NULL)) != LDAP_SUCCESS) {
			fprintf(stderr, "ldap bind failure (%d) [%s]\n", rc, ldap_err2string(rc));
			rc = 1;
			goto done;
		}
		unsetenv("KRB5CCNAME");
	} else {
		struct external_defaults *defs = malloc(sizeof(struct external_defaults));
		defs->bind = conf->ldap.bind;
		defs->pw   = conf->ldap.pw;
		if ((rc = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL,
					LDAP_SASL_QUIET, sasl_interact, (void *)defs)) != LDAP_SUCCESS) {
			fprintf(stderr, "ldap bind failure (%d) [%s]\n", rc, ldap_err2string(rc));
			rc = 1;
			goto done;
		}
		free(defs);
	}

done:
	return ld;
}

void print_attr(LDAP *ld, char *dn, char *att)
{
	LDAPMessage *result = NULL, *e;
	int rc;
	char *attrs[] = { att,  NULL};
	if ((rc = ldap_search_ext_s(ld, dn, LDAP_SCOPE_SUBTREE, NULL, attrs, 0, NULL, NULL, LDAP_NO_LIMIT,
		LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS) {
		printf("ldap search failure (%d) [%s]\n", rc, ldap_err2string(rc));
		exit(1);
	}
	if ((e = ldap_first_entry(ld, result)) == NULL) {
		printf("no results\n");
		exit(0);
	}
	char *attr_name;
	BerElement *ber;
	struct berval **vals;
	for (attr_name = ldap_first_attribute(ld, e, &ber); attr_name != NULL;
			attr_name = ldap_next_attribute(ld, e, ber)) {
		printf("%s: ", attr_name);
		if ((vals = ldap_get_values_len(ld, e, attr_name)) != NULL) {
			for (int i = 0; vals[i] != NULL; i++) {
				if (i == 0)
					printf("%s", vals[i]->bv_val);
				else
					printf(", %s", vals[i]->bv_val);
			}
			ldap_value_free_len(vals);
		}
		printf("\n");
	}
	ldap_memfree(attr_name);
}

int fetch_config(LDAP *ld, config_t *conf, ccert_t *in)
{
	LDAPMessage *result = NULL, *e;
	int rc;
	char *dn = malloc(strlen("cn=conductor,") + strlen(conf->ldap.dn));
	strcpy(dn, "cn=conductor,");
	strcat(dn, conf->ldap.dn);
	char *attrs[] = { "ou", "cn", "o", "st", "l", "c", "conductorIntermediateCert", "conductorIntermediateKey",  NULL};
	if ((rc = ldap_search_ext_s(ld, dn, LDAP_SCOPE_SUBTREE, NULL, attrs, 0, NULL, NULL, LDAP_NO_LIMIT,
		LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS) {
		printf("ldap search failure (%d) [%s]\n", rc, ldap_err2string(rc));
		return 1;
	}
	if ((e = ldap_first_entry(ld, result)) == NULL) {
		printf("no results\n");
		return 1;
	}
	char *attr_name;
	BerElement *ber;
	struct berval **vals;
	for (attr_name = ldap_first_attribute(ld, e, &ber); attr_name != NULL;
			attr_name = ldap_next_attribute(ld, e, ber)) {
		if ((vals = ldap_get_values_len(ld, e, attr_name)) != NULL) {
			for (int i = 0; vals[i] != NULL; i++) {
				if (strcmp(attr_name, "cn") == 0) {
					
				}
				if (strcmp(attr_name, "o")  == 0) {
					if (conf->org.o != NULL)
						free(conf->org.o);
					conf->org.o = strdup((char *)vals[i]->bv_val);
				}
				if (strcmp(attr_name, "ou") == 0) {
					if (conf->org.ou != NULL)
						free(conf->org.ou);
					conf->org.ou = strdup((char *)vals[i]->bv_val);
				}
				if (strcmp(attr_name, "l")  == 0) {
					if (conf->org.l != NULL)
						free(conf->org.l);
					conf->org.l = strdup((char *)vals[i]->bv_val);
				}
				if (strcmp(attr_name, "st") == 0) {
					if (conf->org.st != NULL)
						free(conf->org.st);
					conf->org.st = strdup((char *)vals[i]->bv_val);
				}
				if (strcmp(attr_name, "c")  == 0) {
					if (conf->org.c != NULL)
						free(conf->org.c);
					conf->org.c = strdup((char *)vals[i]->bv_val);
				}
				if (strcmp(attr_name, "conductorIntermediateCert") == 0) {
					if (in->crt != NULL)
						free(in->crt);
					BIO *bio = NULL;
					BUF_MEM *bptr = malloc(sizeof(BUF_MEM));
					bptr->length = vals[i]->bv_len;
					bptr->data   = vals[i]->bv_val;
					BIO_set_mem_buf(bio, bptr, BIO_NOCLOSE);
					in->crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
					if (in->crt == NULL)
						return 1;
				}
				if (strcmp(attr_name, "conductorIntermediateKey")  == 0) {
					if (in->key != NULL)
						free(in->key);
					BIO *bio = NULL;
					BUF_MEM *bptr = malloc(sizeof(BUF_MEM));
					bptr->length = vals[i]->bv_len;
					bptr->data   = vals[i]->bv_val;
					BIO_set_mem_buf(bio, bptr, BIO_NOCLOSE);
					in->key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
					if (in->key == NULL)
						return 1;
				}
			}
			ldap_value_free_len(vals);
		}
	}
	ldap_memfree(attr_name);
	return 0;
}

static void _mod_add_strings(LDAPMod *mod, char *type, char **vals)
{
	mod = malloc(sizeof(LDAPMod));
	mod->mod_type   = type;
	mod->mod_values = vals;
}

static int _mod_add_cert(LDAPMod *mod, char *type, X509 *crt)
{
	mod = malloc(sizeof(LDAPMod));
	mod->mod_op    =  LDAP_MOD_BVALUES;
	mod->mod_type  = type;
	struct berval *conductorCertVals[2];
	BIO *bio = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_X509(bio, crt))
		return 1;
	BUF_MEM *bptr;
	BIO_get_mem_ptr(bio, &bptr);
	conductorCertVals[0]->bv_len = bptr->length;
	memcpy(conductorCertVals[0]->bv_val, bptr->data, bptr->length);
	conductorCertVals[1] = NULL;
	mod->mod_values = (char **) conductorCertVals;
	BIO_free_all(bio);

	return 0;
}

static int _mod_add_key(LDAPMod *mod, char *type, EVP_PKEY *key)
{
	mod = malloc(sizeof(LDAPMod));
	mod->mod_op   =  LDAP_MOD_BVALUES;
	mod->mod_type = type;
	struct berval *conductorKeyVals[2];
	BIO *bio = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL))
		return 1;
	BUF_MEM *bptr;
	BIO_get_mem_ptr(bio, &bptr);
	conductorKeyVals[0]->bv_len = bptr->length;
	memcpy(conductorKeyVals[0]->bv_val, bptr->data, bptr->length);
	conductorKeyVals[1] = NULL;
	mod->mod_values = (char **) conductorKeyVals;
	BIO_free_all(bio);

	return 0;
}

int upload_cert(LDAP *ld, ccert_t *cert)
{
	int rc;
	LDAPMod **mods;
	if ((mods = malloc(sizeof(LDAPMod *) * 5)) == NULL)
		return 1;

	char *cn[] = { cert->cn, NULL };
	_mod_add_strings(mods[0], "cn", cn);

	char *val[] = { "conductor", "top", NULL };
	_mod_add_strings(mods[1], "objectClass", val);

	if (_mod_add_cert(mods[2], "conductorCert", cert->crt) != 0)
		return 1;
	if (_mod_add_key(mods[3], "conductorKey", cert->key) != 0)
		return 1;

	mods[4] = (LDAPMod *) NULL;

	if ((rc = ldap_add_ext_s(ld, cert->dn, mods, NULL, NULL)) != LDAP_SUCCESS)
		printf("ldap failed to add cert, %s (%d) [%s]\n", cert->cn, rc, ldap_err2string(rc));

	return rc;
}

int initialize(LDAP *ld, config_t *conf, ccert_t *ca, ccert_t *in)
{
	int rc = 0;
	char *dn = "cn=conductor,";
	strcat(dn, conf->ldap.dn);

	LDAPMod **mods;
	mods = malloc(sizeof(LDAPMod *) * 12);
	char *cn[] = { "cn=conductor", NULL };
	_mod_add_strings(mods[0], "cn", cn);

	char *val[] = { "conductorContainer", "top", NULL };
	_mod_add_strings(mods[1], "objectClass", val);

	_mod_add_cert(mods[2], "conductorCaCert", ca->crt);
	_mod_add_key(mods[3], "conductorCaKey", ca->key);

	_mod_add_cert(mods[4], "conductorIntermediateCert", in->crt);
	_mod_add_key(mods[5], "conductorIntermediateKey", in->key);

	char *o[]  = { conf->org.o,  NULL };
	_mod_add_strings(mods[6], "o", o);
	char *ou[] = { conf->org.ou, NULL };
	_mod_add_strings(mods[7], "ou", ou);
	char *l[]  = { conf->org.l,  NULL };
	_mod_add_strings(mods[8], "l", l);
	char *st[] = { conf->org.st, NULL };
	_mod_add_strings(mods[9], "st", st);
	char *c[]  = { conf->org.c,  NULL };
	_mod_add_strings(mods[10], "c", c);

	mods[11] = (LDAPMod *) NULL;

	if ((rc = ldap_add_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS)
		printf("ldap failed to initialize conductor container (%d) [%s]\n", rc, ldap_err2string(rc));

	return rc;
}
