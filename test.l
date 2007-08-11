%option never-interactive case-insensitive warn nodefault nounput
%x incl
%{
#include <errno.h>
%}

%%

#[^\n]* 	;
\"[^"\n]+[\"\n] ECHO;
[ \t\r]+ 	;
\n		;
[0-9]+ 		ECHO;
INCLUDE		BEGIN(incl);
.		return yytext[0];

<incl>[ \t]*	/* consume whitespace */
<incl>[^ \t\n]+ {
    yyin = fopen(yytext, "r");
    if (!yyin)
    {
      fprintf(stderr, "Unable to open %s: %s\n", yytext, strerror(errno));
      exit(1);
    }
    yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));
    BEGIN(INITIAL);
    }
<incl>\n	return yytext[0];
<<EOF>> {
    yypop_buffer_state();
    if (!YY_CURRENT_BUFFER)
      yyterminate();
}

%%
