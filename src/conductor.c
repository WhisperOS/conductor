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

int auth(config_t *conf)
{
	LDAP *ld;
	int rc, protocol = LDAP_VERSION3;
	if ((rc = ldap_initialize(&ld, conf->ldap.uri)) != LDAP_SUCCESS) {
		fprintf(stderr, "ldap init failure (%d) [%s]\n", rc, ldap_err2string(rc));
		return 1;
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
	return rc;
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

int upload_cert(LDAP *ld, ccert_t *cert)
{
	int rc;
	LDAPMod **mods;
	mods = malloc(sizeof(LDAPMod *) * 5);

	mods[0] = malloc(sizeof(LDAPMod));
	mods[0]->mod_type   = "cn";
	char *cn[] = { cert->cn, NULL };
	mods[0]->mod_values = cn;

	mods[1] = malloc(sizeof(LDAPMod));
	mods[1]->mod_type   = "objectClass";
	char *class[] = { "conductorEntry", "top", NULL };
	mods[1]->mod_values = class;

	mods[2] = malloc(sizeof(LDAPMod));
	mods[2]->mod_op     =  LDAP_MOD_BVALUES;
	mods[2]->mod_type   = "conductorCert";
	struct berval *conductorCertVals[2];
	BIO *bio = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_X509(bio, cert->crt))
		return 1;
	BUF_MEM *bptr;
	BIO_get_mem_ptr(bio, &bptr);
	conductorCertVals[0]->bv_len = bptr->length;
	conductorCertVals[0]->bv_val = bptr->data;
	conductorCertVals[1] = NULL;
	mods[2]->mod_values = (char **) conductorCertVals;
	BIO_free_all(bio);

	mods[3] = malloc(sizeof(LDAPMod));
	mods[3]->mod_op     =  LDAP_MOD_BVALUES;
	mods[3]->mod_type   = "conductorKey";

	struct berval *conductorKeyVals[2];
	bio = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_PrivateKey(bio, cert->key, NULL, NULL, 0, NULL, NULL))
		return 1;
	BIO_get_mem_ptr(bio, &bptr);
	conductorKeyVals[0]->bv_len = bptr->length;
	conductorKeyVals[0]->bv_val = bptr->data;
	conductorKeyVals[1] = NULL;
	mods[3]->mod_values = (char **) conductorKeyVals;
	BIO_free_all(bio);

	mods[4] = (LDAPMod *) NULL;

	if ((rc = ldap_add_ext_s(ld, cert->dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
		printf("ldap failed to add (%d) [%s]\n", rc, ldap_err2string(rc));
	}
	return 0;
}
