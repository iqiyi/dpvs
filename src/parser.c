/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <glob.h>
#include "global_data.h"
#include "conf/common.h"
#include "parser/parser.h"

/* exported global vars */
vector_t g_keywords;
FILE *g_current_stream;
bool g_reload = false;

/* global vars */
static vector_t g_current_keywords;
static char *g_current_conf_file;
static int g_sublevel = 0;

/*
 * keyword operations
 * */

/* allocate and set a keyword in current level */
void keyword_alloc(vector_t keywords_vec, char *str, keyword_callback_t handler)
{
    struct keyword *keywd;

    vector_alloc_slot(keywords_vec);

    keywd = (struct keyword *) MALLOC(sizeof(struct keyword));
    keywd->str = str;
    keywd->handler = handler;

    vector_set_slot(keywords_vec, keywd);
}

/* allocate and set a keyword in last sub level */
void keyword_alloc_sub(vector_t keywords_vec, char *str, keyword_callback_t handler)
{
    int i = 0;
    struct keyword *keywd;

    /* fetch last keyword */
    keywd = VECTOR_SLOT(keywords_vec, VECTOR_SIZE(keywords_vec) - 1);

    /* position to last sub level */
    for (i = 0; i < g_sublevel; i++)
        keywd = VECTOR_SLOT(keywd->sub, VECTOR_SIZE(keywd->sub) - 1);

    /* first sub level allocation */
    if (!keywd->sub)
        keywd->sub = vector_alloc();

    /* add new sub keyword */
    keyword_alloc(keywd->sub, str, handler);
}

void free_keywords(vector_t keywords)
{
    struct keyword *keywd;
    int i;

    for (i = 0; i < VECTOR_SIZE(keywords); i++) {
        keywd = VECTOR_SLOT(keywords, i);
        if (keywd->sub)
            free_keywords(keywd->sub);
        FREE(keywd);
    }
    vector_free(keywords);
}

#ifdef DPVS_CFG_PARSER_DEBUG
void dump_keywords(vector_t keywords, int level)
{
    int i, j;
    struct keyword *keywd;

    for (i = 0; i < VECTOR_SIZE(keywords); i++) {
        keywd = VECTOR_SLOT(keywords, i);
        for (j = 0; j < level; j++)
            printf("  ");
        printf("keyword: %s\n", keywd->str);
        if (keywd->sub)
            dump_keywords(keywd->sub, level + 1);
    }
}
#endif

/*
 * keyword helpers
 */
void install_sublevel(void)
{
    g_sublevel++;
}

void install_sublevel_end(void)
{
    g_sublevel--;
}

void install_keyword_root(char *str, keyword_callback_t handler)
{
    keyword_alloc(g_keywords, str, handler);
}

void install_keyword(char *str, keyword_callback_t handler, keyword_type_t type)
{
    if ((type == KW_TYPE_INIT) &&
            (dpvs_state_get() != DPVS_STATE_INIT))
        handler = NULL;/* skip keywords only for initialization stage */

    keyword_alloc_sub(g_keywords, str, handler);
}

/*
 * split string into tokens
 */
static vector_t tokenize_string(const char *str)
{
    const char *pos, *start;
    char *token;
    int str_len;
    vector_t token_vec;

    if (!str)
        return NULL;

    pos = str;

    /* skip white spaces */
    while (isspace((int) *pos) && *pos != '\0')
        pos++;

    /* return if there is only white spaces */
    if (*pos == '\0')
        return NULL;

    /* return if str begin with a commit */
    if (*pos == '!' || *pos == '#')
        return NULL;

    /* create a vector and alloc each command piece */
    token_vec = vector_alloc();

    while (1) {
        start = pos;
        if (*pos == '"') {
            pos++;
            token = MALLOC(2);
            *token = '"';
            *(token + 1) = '\0';
        } else {
            while (!isspace((int) *pos) && *pos != '\0' && *pos != '"')
                pos++;
            /* this is an attribute, ignore */
            if (*start == '<') {
                while (*(pos - 1) != '>' && *pos != '\0')
                    pos++;
                while(isspace((int) *pos) && *pos != '\0')
                    pos++;
                if (*pos == '\0' || *pos == '!' || *pos == '#')
                    return token_vec;
                continue;
            }
            /* save this token */
            str_len = pos - start;
            token = MALLOC(str_len + 1);
            memcpy(token, start, str_len);
            *(token + str_len) = '\0';
        }

        /* allocate and set the slot */
        vector_alloc_slot(token_vec);
        vector_set_slot(token_vec, token);

        while (isspace((int) *pos) && *pos != '\0')
            pos++;
        if (*pos == '\0' || *pos == '!' || *pos == '#')
            return token_vec;
    }
}

/*
 * read each line in conf file and included conf file, then invoke
 * registered callbacks * provided by g_current_keywords.
 */
void read_conf_file(char *conf_file)
{
    FILE *stream;
    int i;
    char *confpath;
    char prev_path[CFG_FILE_MAX_BUF_SZ];

    glob_t globbuf = { .gl_offs = 0, };
    glob(conf_file, 0, NULL, &globbuf);

    for (i = 0; i < globbuf.gl_pathc; i++) {
        RTE_LOG(INFO, CFG_FILE, "Opening configuration file '%s'.\n", globbuf.gl_pathv[i]);
        stream = fopen(globbuf.gl_pathv[i], "r");
        if (!stream) {
            RTE_LOG(WARNING, CFG_FILE, "Fail to open configuration file '%s': %s.\n",
                    globbuf.gl_pathv[i], strerror(errno));
            return;
        }

        g_current_stream = stream;
        g_current_conf_file = globbuf.gl_pathv[i];
        if (getcwd(prev_path, CFG_FILE_MAX_BUF_SZ) != NULL) {
            confpath= strdup(globbuf.gl_pathv[i]);
            dirname(confpath);
            if (chdir(confpath) == 0) {
                process_stream(g_current_keywords);
                if (chdir(prev_path) != 0)
                    RTE_LOG(ERR, CFG_FILE, "Fail to chdir()\n");
            }
            free(confpath);
        }
        fclose(stream);
    }

    globfree(&globbuf);
}

/*
 * check included configuration file, read it if exists.
 */
int check_include(char *buf)
{
    char *str;
    vector_t token_vec;

    token_vec = tokenize_string(buf);
    if (!token_vec)
        return 0;

    str = VECTOR_SLOT(token_vec, 0);
    if (!strcmp(str, CFG_FILE_EOB)) {
        vector_str_free(token_vec);
        return 0;
    }

    if (!strcmp("include", str) && VECTOR_SIZE(token_vec) == 2) {
        char *conf_file = VECTOR_SLOT(token_vec, 1);
        FILE *prev_stream = g_current_stream;
        char *prev_conf_file = g_current_conf_file;
        char prev_path[CFG_FILE_MAX_BUF_SZ];

        if (getcwd(prev_path, CFG_FILE_MAX_BUF_SZ) != NULL) {
            read_conf_file(conf_file);

            g_current_stream = prev_stream;
            g_current_conf_file = prev_conf_file;
            if (chdir(prev_path) != 0)
                RTE_LOG(ERR, CFG_FILE, "Fail to chdir()\n");

            vector_str_free(token_vec);
        }
        return 1;
    }

    vector_str_free(token_vec);
    return 0;
}

/*
 * read a line from configuration file into buf, check and parse
 * included files if exist.
 */
int read_line(char *buf, int size)
{
    assert(size <= CFG_FILE_MAX_BUF_SZ);
    int ch;

    do {
        int count = 0;
        memset(buf, 0, CFG_FILE_MAX_BUF_SZ);
        while ((ch = fgetc(g_current_stream)) != EOF &&
                (int) ch != '\n' &&
                (int) ch != '\r') {
            if (count < size)
                buf[count] = (int) ch;
            else
                break;
            count++;
        }
    } while (check_include(buf) == 1);

    return (ch == EOF) ? 0 : 1;
}

/*
 * read a block of current configuration file and return corresponding
 * tokens in vector.
 */
vector_t read_value_block(void)
{
    int i;
    char *dup, *str = NULL;
    char *buf;
    vector_t tokens = NULL;
    vector_t block_tokens = vector_alloc();

    buf = (char *) MALLOC(CFG_FILE_MAX_BUF_SZ);
    while (read_line(buf, CFG_FILE_MAX_BUF_SZ)) {
        tokens = tokenize_string(buf);
        if (tokens) {
            assert(VECTOR_SIZE(tokens) > 0);

            str = VECTOR_SLOT(tokens, 0);
            if (!strcmp(str, CFG_FILE_EOB)) {
                vector_str_free(tokens);
                break;
            }

            for (i = 0; i < VECTOR_SIZE(tokens); i++) {
                str = VECTOR_SLOT(tokens, i);
                dup = (char *) MALLOC(strlen(str) + 1);
                memcpy(dup, str, strlen(str));
                vector_alloc_slot(block_tokens);
                vector_set_slot(block_tokens, dup);
            }
            vector_str_free(tokens);
        }
        memset(buf, 0, CFG_FILE_MAX_BUF_SZ);
    }

    FREE(buf);
    return block_tokens;
}

/*
 * read a block of current configuration file and revoke alloc_func
 * with each tokenized string line.
 */
void alloc_value_block(void (*alloc_func)(vector_t))
{
    char *buf;
    char *str = NULL;
    vector_t tokens = NULL;

    buf = (char *) MALLOC(CFG_FILE_MAX_BUF_SZ);
    while (read_line(buf, CFG_FILE_MAX_BUF_SZ)) {
        tokens = tokenize_string(buf);
        if (tokens) {
            assert(VECTOR_SIZE(tokens) > 0);

            str = VECTOR_SLOT(tokens, 0);
            if (!strcmp(str, CFG_FILE_EOB)) {
                vector_str_free(tokens);
                break;
            }
            alloc_func(tokens);
        }
        memset(buf, 0, CFG_FILE_MAX_BUF_SZ);
    }
    FREE(buf);
}

/*
 * return value string of a keyword from its token vector
 */
void *set_value(vector_t tokens)
{
    assert(VECTOR_SIZE(tokens) > 1);

    char *str = VECTOR_SLOT(tokens, 1);
    int size = strlen(str);
    int i = 0, len = 0;
    char *alloc = NULL;
    char *tmp;

    if (*str == '"') {
        for (i = 2; i < VECTOR_SIZE(tokens); i++) {
            str = VECTOR_SLOT(tokens, i);
            len += strlen(str);
            if (!alloc)
                alloc = (char *) MALLOC(sizeof(char *) * (len + 1));
            else {
                alloc = REALLOC(alloc, sizeof(char *) * (len + 1));
                tmp = VECTOR_SLOT(tokens, i - 1);
                if ( *str != '"' && *tmp != '"')
                    strncat(alloc, " ", 1);
            }

            if (i != VECTOR_SIZE(tokens) - 1)
                strncat(alloc, str, strlen(str));
        }
    } else {
        alloc = MALLOC(sizeof(char) * (size + 1));
        memcpy(alloc, str, size + 1);
    }

    return alloc;
}

/*
 * recursive configuration stream handler
 */
static int g_keyword_level = 0;
void process_stream(vector_t keywords)
{
    int i;
    struct keyword *kw;
    char *str;
    char *buf;
    bool isfound;
    vector_t tokens;
    vector_t prev_keywords = g_current_keywords;
    g_current_keywords = keywords;

    buf = (char *) MALLOC(CFG_FILE_MAX_BUF_SZ);
    memset(buf, 0, CFG_FILE_MAX_BUF_SZ);
    while (read_line(buf, CFG_FILE_MAX_BUF_SZ)) {
        isfound = false;
        tokens = tokenize_string(buf);
        memset(buf, 0, CFG_FILE_MAX_BUF_SZ);
        if (!tokens)
            continue;

        assert(VECTOR_SIZE(tokens) > 0);
        str = VECTOR_SLOT(tokens, 0);
        if (!strcmp(str, CFG_FILE_EOB) && g_keyword_level > 0) {
            vector_str_free(tokens);
            break;
        }

        for (i = 0; i < VECTOR_SIZE(g_current_keywords); i++) {
            kw = VECTOR_SLOT(g_current_keywords, i);
            if (!strcmp(kw->str, str)) {
                isfound = true;
                if (kw->handler)
                    (*kw->handler)(tokens);
                if (kw->sub) {
                    g_keyword_level++;
                    process_stream(kw->sub);
                    g_keyword_level--;
                }
                break;
            }
        }

        if (!isfound && str[0] != '}')
            RTE_LOG(WARNING, CFG_FILE, "not supported keyword -- %s\n", str);

        vector_str_free(tokens);
    }

    g_current_keywords = prev_keywords;
    FREE(buf);
}

/*
 * data initialization
 */
void init_data(char *conf_file, vector_t (*init_keywords)(void))
{
    /* init keywords structure */
    g_keywords = vector_alloc();
    (*init_keywords)();

#ifdef DPVS_CFG_PARSER_DEBUG
    /* dump configuration */
    vector_dump(g_keywords);
    dump_keywords(g_keywords, 0);
#endif

    /* stream handling */
    g_current_keywords = g_keywords;
    read_conf_file(conf_file ? conf_file : dpvs_conf_file);

    free_keywords(g_keywords);
}
