/*
 *      Code to convert a stream input into a dynamic array
 *      that can be parsed as argc and argv.
 *
 *      Authors: Horms <horms@vergenet.net>
 *
 *      Released under the terms of the GNU GPL
 *
 *      ChangeLog
 *      Horms         :   scanf Glibc under Red Hat 7 does not appear
 *                        to return EOF when input ends. Fall through
 *                        code has been added to handle this case correctly
 */

#include "config_stream.h"


/**********************************************************************
 * config_stream_read
 * Read in a config file and put elements in a dynamic array
 * pre: stream: stream to read configuration from
 * return: dynamic array whose elements are the space delimited
 *         tokens read from the stream. Result is returned
 *         once a newline is reached so multiple calls
 *         will be required to read an entire stream.
 *         Everything including and after a hash (#) on a line is
 *         ignored
 **********************************************************************/

dynamic_array_t *
config_stream_read(FILE * stream, const char *first_element)
{
  char token[MAX_LINE_LENGTH];
  char tail[2];
  char format[MAX_LINE_LENGTH];
  char format_whitespace[MAX_LINE_LENGTH];
  int status;
  int ntoken;
  int comment = 0;
  char *s;
  int c;
  int flag;
  dynamic_array_t *a;

  if ((a = dynamic_array_create((size_t) 0)) == NULL) {
    perror("config_file_read: dynamic_array_create");
    return (NULL);
  }

  /*insert a argv[0] into the dynamic array */
  if ((a = dynamic_array_add_element(a,
				     (first_element !=
				      NULL ? first_element : ""),
				     DESTROY_STR, DUP_STR)) == NULL) {
    perror("config_file_read: dynamic_array_add_element");
    return (NULL);
  }

  sprintf(format, "%%%d[^ \t\n\r]%%1[ \t\n\r]", MAX_LINE_LENGTH);
  sprintf(format_whitespace, "%%%d[ \t\r]%%1[\n]", MAX_LINE_LENGTH);

  ntoken = 0;
  while ((status = fscanf(stream, format, token, tail)) != EOF) {
    if (status == 0) {
      flag = 1;
      while (flag) {
	c = fgetc(stream);
	switch (c) {
	case EOF:
	  dynamic_array_destroy(a, DESTROY_STR);
	  return (NULL);
	case '\n':
	  return (a);
	case '\t':
	case '\r':
	case ' ':
	  break;
	default:
	  ungetc(c, stream);
	  flag = 0;
	}
      }
      continue;
    }
    if (!comment && strcmp(token, "ipvsadm")) {
      ntoken++;
      if ((a = dynamic_array_add_element(a,
					 token,
					 DESTROY_STR, DUP_STR)) == NULL) {
	perror("config_file_read: dynamic_array_add_element");
	dynamic_array_destroy(a, DESTROY_STR);
	return (NULL);
      }
    }
    if ((s = strrchr(tail, '\n')) != NULL) {
      return (a);
    }
    if (!comment) {
      comment = (strchr((s != NULL ? s : tail), '#') == NULL) ? 0 : 1;
    }
  }

  if (ntoken == 0) {
    dynamic_array_destroy(a, DESTROY_STR);
    return (NULL);
  }

  return (a);
}
