/*
 *      Code to convert a stream input into a dynamic array
 *      that can be parsed as argc and argv.
 *
 *      Authors: Horms <horms@vergenet.net>
 *
 *      Released under the terms of the GNU GPL
 */

#ifndef CONFIG_STREAM_FLIM
#define CONFIG_STREAM_FLIM

#include "dynamic_array.h"

#define MAX_LINE_LENGTH 4096

dynamic_array_t *config_stream_read(FILE * stream,
				    const char *first_element);

#endif
