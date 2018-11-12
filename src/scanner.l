/*
 * Copyright 2015,2018 Dan Molik <dan@danmolik.com>
 *
 * This file is part of Shitty Little Server
 *
 * Shitty Little Server is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * Shitty Little Server is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with Shitty Little Server.  If not, see <http://www.gnu.org/licenses/>.
 */

%{
#include "config_file.h"
#include <string.h>
#include <stdio.h>
#include "utils.h"
#include "parse.h"
%}

%option yylineno
%option noinput nounput
%option never-interactive

%x LIST

LOG_TYPE     (?i:console|syslog|file)
LOG_LEVEL    (?i:warn|warning|error|notice|debug|info|crit|critical|emerg|emergency)
LOG_FACILITY (?i:kern|user|mail|daemon|auth|syslog|lpr|news|uucp|clock|12|13|14|authpriv|ftp|cron|local[0-7])
DECIMAL      ([0-9]+\.[0-9]+)
INT          ([0-9]+)
STRING       ([0-9A-Za-z_\/:\-\=,\.]+)
PASSWD       ([0-9A-Za-z_\/\-\=\/\:\.\!\@\$\%^&\*\[\}\{\\]\;\?,]+)
SENTANCE     ([0-9A-Za-z_\/:\.\-]+)

%%

<INITIAL>{
	/* options */
	pidfile  { return PIDFILE;  }
	user     { return USER;     }
	group    { return GROUP;    }
	workers  { return WORKERS;  }
	sessions { return SESSIONS; }
	type     { return LOGTYPE;  }
	level    { return LOGLEVEL; }
	facility { return FACILITY; }
	port     { return PORT;     }
	cert     { return CERT;     }
	ca       { return CA;       }
	key      { return KEY;      }
	log      { return LOG;      }

	ldap   { return LDAP; }
	uri    { return URI;  }
	dn     { return DN;   }
	binddn { return BIND; }
	pw     { return PW;   }

	org { return ORG; }
	c   { return C;   }
	o   { return O;   }
	l   { return L;   }
	st  { return ST;  }
	ou  { return OU;  }

	krb5       { return KRB5; }
	keytab     { return KEYTAB; }
	princ      { return PRINC; }
	principal  { return PRINC; }
}

<LIST>{
	/* start the list macro */
	/* "{" {
	      BEGIN INITIAL;
	      return *yytext;
	    }
	*/
	"}" {
	      BEGIN INITIAL;
	      return *yytext;
	    }
	\n* /* suppress new lines */;
}

<INITIAL,LIST>{
	/* pull all the values from the list */
	{LOG_LEVEL} {
	              yylval.string = strdup(yytext);
	              return LOG_LEVEL;
	            }
	{LOG_TYPE} {
	             yylval.string = strdup(yytext);
	             return LOG_TYPE;
	           }
	{LOG_FACILITY} {
	                 yylval.string = strdup(yytext);
	                 return LOG_FACILITY;
	               }
	{DECIMAL} {
	            yylval.d = atof(yytext);
	            return DECIMAL;
	          }
	{INT}     {
	            yylval.i = atoi(yytext);
	            return INT;
	          }
	{STRING}  {
	            yylval.string = strdup(yytext);
	            return STRING;
	          }
	{PASSWD}  {
	            yylval.string = strdup(yytext);
	            return STRING;
	          }
	#.*       /* ignore comments */;
	[\n\r]*   /* ignore new lines */;
	[\ \t]*   /* ignore whitespace */;
	\\\n      /* ignore linebreaks */;
	.|\n      { return *yytext; }
}

%%