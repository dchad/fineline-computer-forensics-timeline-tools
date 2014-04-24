/*  Copyright 2014 Derek Chadwick
 
    This file is part of the FineLine Computer Forensics Timeline Tools.

    FineLine is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FineLine is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FineLine.  If not, see <http://www.gnu.org/licenses/>.
*/


/*
   fineline.h

   Title : FineLine Computer Forensics Internet Explorer Cache Parser
   Author: Derek Chadwick
   Date  : 02/03/2014

   Purpose: FineLine global definitions.

*/

#ifdef LINUX_BUILD

#include <sys/types.h>
#include <sys/socket.h>


#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#endif

#define HAVE_LOCAL_LIBCERROR
#define HAVE_LOCAL_LIBCSTRING
#define HAVE_LOCAL_LIBFDATETIME

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <libesedb.h>
#include <libcerror_definitions.h>
#include <libcerror_error.h>
#include <libcerror_system.h>
#include <libcerror_types.h>


#include "uthash.h"

/*
   Constant Definitions
*/

#define DEBUG 0

#define GUI_SERVER_PORT_STRING "58989"

#define FL_PATH_MAX 4096 /* Redefine max path length since limits.h does weird things! */
#define FL_MAX_INPUT_STR 4096
#define FL_IP_ADDR_MAX 128
#define MAX_EVENT_DESC_SIZE 256
#define MAX_EVENT_ID_SIZE 8

#define FL_FILE_OUT  0x01
#define FL_GUI_OUT   0x02
#define FL_INDEX_IN  0x04  /* This is the IE1-9 index.dat */
#define FL_CACHE_IN  0x08  /* This is the IE10+ WebCacheV01.dat */
#define FL_FILTER_ON 0x10

#define DATABASE_FILE_EXT ".txt"
#define EVENT_FILE_EXT ".fle"
#define FL_URL_FILTER_LIST "fl-url-filter-list.txt"
#define IE_CACHE_FILE "WebCacheV01.dat"

#ifdef LINUX_BUILD
#define PATH_SEPARATOR "/"
#define CURRENT_DIR "./"
#define CONFIG_FILE "./fineline-linux.conf"
#define LOG_FILE "./fineline-linux.log"
#define DATABASE_FILE "./fineline-event-linux"
#define BINARY_FILE "./fineline"
#define MESSAGE_LOG_FILE "/var/log/messages"
#define SECURITY_LOG_FILE "/var/log/security"
#define EVENT_FILE "fineline-events"
#define EVENT_LOG_PATH "./"
#define IE_CACHE_PATH "./"
#else
#define PATH_SEPARATOR "\\"
#define CURRENT_DIR ".\\"
#define CONFIG_FILE ".\\fineline.conf"
#define LOG_FILE ".\\fineline.log"
#define DATABASE_FILE "fineline-events"
#define EVENT_FILE "fineline-events"
#define IE_CACHE_PATH "C:\\Windows\\System32\\winevt\\Logs"
#endif /* LINUX_BUILD */

/*
   REGEXs
*/

#define BEST_REGEX "/^.*(?=.{6,})(?=.*[A-Z])(?=.*[\d])(?=.*[\W]).*$/"
#define STRONG_REGEX "/^[a-zA-Z\d\W_]*(?=[a-zA-Z\d\W_]{6,})(((?=[a-zA-Z\d\W_]*[A-Z])(?=[a-zA-Z\d\W_]*[\d]))|((?=[a-zA-Z\d\W_]*[A-Z])(?=[a-zA-Z\d\W_]*[\W_]))|((?=[a-zA-Z\d\W_]*[\d])(?=[a-zA-Z\d\W_]*[\W_])))[a-zA-Z\d\W_]*$/"
#define WEAK_REGEX "/^[a-zA-Z\d\W_]*(?=[a-zA-Z\d\W_]{6,})(?=[a-zA-Z\d\W_]*[A-Z]|[a-zA-Z\d\W_]*[\d]|[a-zA-Z\d\W_]*[\W_])[a-zA-Z\d\W_]*$/"
#define BAD_REGEX "/^((^[a-z]{6,}$)|(^[A-Z]{6,}$)|(^[\\d]{6,}$)|(^[\\W_]{6,}$))$/"

/*
DATA STRUCTURES
*/

struct fl_project_header
{
   char *name;
   char *investigator;
   char *summary;
   char *start_date;
   char *end_date;
   char *description;
   int event_count;
};

typedef struct fl_project_header fl_project_header_t;

struct fl_url_record
{
   int id;
   double url_time;
   uint64_t access_count;
   int day;
   int month;
   int year;
   char url_time_string[32];
   char url_record_string[FL_MAX_INPUT_STR];
   UT_hash_handle hh;
};

typedef struct fl_url_record fl_url_record_t;

struct fl_url_filter
{
   int url_id;
   char url_string[FL_MAX_INPUT_STR];
   UT_hash_handle hh;
};

typedef struct fl_url_filter fl_url_filter_t;


/*
   ENUMs
*/

enum op_modes { FL_DB_MODE = 1, FL_DB_MODE_X, FL_GUI_MODE, FL_GUI_MODE_X, FL_GUI_AND_DB_MODE, FL_GUI_AND_DB_MODE_X };
enum error_codes { SUCCESS, FILE_ERROR, INTEGRITY_ERROR, MALLOC_ERROR, SYSTEM_ERROR, UNKNOWN_ANOMALY };
enum log_modes { LOG_ERROR, LOG_WARNING, LOG_INFO };

/*
   Function Prototypes
*/

/* fineline-ie.c */
int parse_command_line_args(int argc, char *argv[], char *fl_filename, char *in_file, char *gui_ip_address, char *filter_filename);

/* fleventfile.c */
FILE *open_fineline_event_file(char *event_file_name);
int close_fineline_event_file(FILE *evt_file);
int write_fineline_project_header(char *pstr, FILE *evt_file, int record_count);
int write_fineline_event_record(char *estr, FILE *evt_file);

/* flutil.c */
int fatal(char *str);
void *xcalloc (size_t size);
void *xmalloc (size_t size);
void *xrealloc (void *ptr, size_t size);
int xfree(char *buf, int len);
int print_help();
char* xitoa(int value, char* result, int len, int base);
int get_time_string(char *tstr, int slen);
int validate_ipv4_address(char *ipv4_addr);
int validate_ipv6_address(char *ipv6_addr);
char *ltrim(char *s);
char *rtrim(char *s);
char *trim(char *s);

/* fllog.c */
int open_log_file(char *startup_path);
int print_log_entry(char *estr);
int close_log_file();

/* fliecacheparser.c */
int parse_ie_cache_file(char *iecfile, char *fl_event_file, int mode, char *gui_ip_addr, char *filter_filename);
int process_cache_url_item(char *url_item);
int process_containers_table(libesedb_file_t *input_file, libesedb_table_t *table, int mode);
int process_history_table(libesedb_file_t *input_file, libesedb_record_t *container_record, int id_column, int mode);
int process_iedownload_table(libesedb_file_t *input_file, libesedb_record_t *container_record, int id_column);
int process_cache_table(libesedb_table_t *table);
int get_table_index(libesedb_file_t *input_file, libesedb_record_t *container_record, int id_column);
int get_container_id_column(libesedb_table_t *table);
int get_date_time_string(libesedb_record_t *record, int column, struct fl_url_record *flurl);
int get_url_string(libesedb_record_t *record, int column, struct fl_url_record *flurl);
int get_access_count(libesedb_record_t *record, int column, int column_type, struct fl_url_record *flurl);
int get_record_index(libesedb_record_t *record, int column, int column_type, struct fl_url_record *flurl);
int format_url_event_string(struct fl_url_record *flurl);

/* flfilterhashmap.c */

int load_url_filters(char *filter_filename);
struct fl_url_filter *find_filter(int url_id);
void add_filter(int url_id, struct fl_url_filter *flurl);
int match_url_filter(char *url_string);

/* flurlhashmap.c */

void add_url_record(uint64_t url_id, struct fl_url_record *flurl);
struct fl_url_record *find_url(uint64_t url_id);
void write_url_map(FILE *outfile);
void write_url_map_in_time_sequence(FILE *outfile, uint64_t lowest);
void send_url_map();
void send_url_map_in_time_sequence(uint64_t lowest);
int time_sort(struct fl_url_record *a, struct fl_url_record *b);
void sort_by_time();
void sort_by_record_number();
void delete_event(struct fl_url_record *url_record);
void delete_all();
struct fl_url_record *get_first_url_record();
struct fl_url_record *get_last_url_record();
uint64_t get_first_record_number();

/* flsocket.c */

int init_socket(char *gui_ip_address);
int send_event(char *event_string);
char *get_response();
int close_socket();


/* Unit Test Functions */
int unit_tests(FILE *log_file);



