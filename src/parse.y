%{
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>

#include "utils.h"
#include "conductor.h"
#include "config_file.h"

config_t *p_config;

int  yylex(void);
void yyerror(char *str, ...);
int  yyval;
int  yyparse();

char temp[1024];
%}


%union
{
	double  d;
	char   *string;
	int     i;
}

%token <d> DECIMAL;
%token <i> INT;
%token <string> STRING;
%token <string> LOG_FACILITY;
%token <string> LOG_TYPE;
%token <string> LOG_LEVEL;
%token <string> SENTANCE;
%token <string> PASSWD;

%token PIDFILE;
%token USER;
%token GROUP;
%token WORKERS;
%token LOG;
%token LOGLEVEL;
%token LOGTYPE;
%token FACILITY;
%token PORT;
%token KEY;
%token CERT;
%token CA;
%token SESSIONS;
%token LDAP;
%token KRB5;
%token ORG;
%token O;
%token OU;
%token L;
%token ST;
%token C;
%token KEYTAB;
%token PRINC;
%token URI;
%token DN;
%token BIND;
%token PW;

%type <string> sentance;
%%

configuration:
	| configuration config
	| configuration LOG optional_eol '{' log_section '}'
	| configuration LDAP optional_eol '{' ldap_section '}'
	| configuration KRB5 optional_eol '{' krb5_section '}'
	| configuration ORG optional_eol '{' org_section '}'
	;

config:
	  PIDFILE  STRING { p_config->pid           = $2;        }
	| USER     STRING { p_config->uid           = $2;        }
	| GROUP    STRING { p_config->gid           = $2;        }
	| WORKERS  INT    { p_config->workers       = $2;        }
	| SESSIONS INT    { p_config->sessions      = $2;        }
	| PORT     INT    { p_config->addr.sin_port = htons($2); }
	| KEY      STRING { p_config->certs.key     = $2;        }
	| CERT     STRING { p_config->certs.chain   = $2;        }
	| CA       STRING { p_config->certs.ca      = $2;        }
	;

log_section:
	| log_section log_statement
	;

log_statement:
	  LOGLEVEL LOG_LEVEL    { p_config->log.level    = $2; }
	| LOGTYPE  LOG_TYPE     { p_config->log.type     = $2; }
	| FACILITY LOG_FACILITY { p_config->log.facility = $2; }
	;

krb5_section:
	| krb5_section krb5_statement
	;

krb5_statement:
	  KEYTAB STRING { p_config->krb5.keytab    = $2; }
	| PRINC  STRING { p_config->krb5.principal = $2; }

ldap_section:
	| ldap_section ldap_statement
	;

ldap_statement:
	  URI    STRING { p_config->ldap.uri   = $2; }
	| DN     STRING { p_config->ldap.dn    = $2; }
	| BIND   STRING { p_config->ldap.bind  = $2; }
	| PW     PASSWD { p_config->ldap.pw    = $2; }
	| PW     STRING { p_config->ldap.pw    = $2; }

org_section:
	| org_section org_statement
	;

sentance: sentance STRING { strcat($1, " "); strcat($1, $2); $$ = $1; }
	| STRING
	;

org_statement:
	  C  STRING   { p_config->org.c  = $2; }
	| ST STRING   { p_config->org.st = $2; }
	| L  STRING   { p_config->org.l  = $2; }
	| OU STRING   { p_config->org.ou = $2; }
	| O  sentance { p_config->org.o  = $2; }
	;

optional_eol:
	| optional_eol '\n'
	;

%%

void yyerror(char *str, ...)
{
	fprintf(stderr, "error: %s\n", str);
	extern int yylineno;
	fprintf (stderr, "configuration file line: %d\n", yylineno);
}

int yywrap()
{
	return 1;
}

int parse_config_file (config_t *config_ref, const char *path)
{
	// parse the configuration file and store the results in the structure referenced
	// error messages are output to stderr
	// Returns: 0 for success, otherwise non-zero if an error occurred
	//
	extern FILE *yyin;
	extern int yylineno;

	p_config = malloc(sizeof(config_t));
	p_config = config_ref;

	yyin = fopen (path, "r");
	if (yyin == NULL) {
		fprintf(stderr, "can't open configuration file %s: %s\n", path, strerror(errno));
		return -1;
	}

	yylineno = 1;
	if (yyparse ()) {
		fclose (yyin);
		return -1;
	} else
		return 0;
}
