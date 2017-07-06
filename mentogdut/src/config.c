#include "mentogdut.h"

//-------------------------------------------------------------------------

struct drcom_config dconfig = {
	.localip = 0,
    .port = 61440,
	.pppoe_flag = '\x6a',
	.keep_alive2_flag = '\xdc',
	.checksum = 0,
};

//-------------------------------------------------------------------------

static int str_strip(char *s, char *chars)
{
	char *p = s;
	while (strchr(chars, *p) != NULL && *p != '\0') {
		++p;
	}

	int len = strlen(p);
	if (p != s) {
		memmove(s, p, len/* + sizeof(p[0])*/);
	} //if

	while (--len >= 0 && strchr(chars, s[len]) != NULL) {}

	s[len + 1] = '\0';

	return len; // upper bound
}

//-------------------------------------------------------------------------

static void parse_line(char *line, int size)
{
	// skip comment
	char *p = strchr(line, '#');
	if (p) *p = '\0';

	p = strchr(line, '=');
	if (p == NULL) return;

	char key[32];
	int maxl  = p - line; 
	maxl      = select_min(maxl, sizeof(key) - 1);
	key[maxl] = '\0';
	strncpy(key, line, maxl);
	int upbound = str_strip(key, " \n\r\t");
	if ((key[0] == '"' && key[upbound] == '"') ||
		(key[0] == '\'' && key[upbound] == '\'')) {
		str_strip(key, "\"'");
	} //if

	++p; // skip '='
	upbound = str_strip(p, " \r\t\n");
	if ((p[0] == '"' && p[upbound] == '"') ||
		(p[0] == '\'' && p[upbound] == '\'')) {
		str_strip(p, "\"'");
	} //if

	if (strcmp(key, "server") == 0) {
		strcpy(dconfig.server, p);
	} else if (strcmp(key, "port") == 0) {
		dconfig.port = (unsigned short)atoi(p);
	} else if (strcmp(key, "pppoe_flag") == 0) {
		dconfig.pppoe_flag = (char)strtol(p, NULL, 16);
	} else if (strcmp(key, "keep_alive2_flag") == 0) {
		dconfig.keep_alive2_flag = (char)strtol(p, NULL, 16);
	} else if (strcmp(key, "checksum") == 0) {
		dconfig.checksum = atoi(p);
	} //if
}

//-------------------------------------------------------------------------

void parse_config(const char *file)
{
    FILE *fp = fopen(file, "r");
	if (fp == NULL) {
		__fprintf(stderr, "failed to open %s!\n", file);
		return;
	} //if

	char line[64];
    while(!feof(fp))
    {
        if (fgets(line, sizeof(line), fp) == NULL) break;
		if (line[0] != '\0') {
			parse_line(line, sizeof(line));
		} //if
    }
    fclose(fp);
}

//-------------------------------------------------------------------------

void set_host_ip(unsigned long ip)
{
	dconfig.localip = ip;
}


