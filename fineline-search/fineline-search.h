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
   fineline-ws.h

   Title : FineLine Computer Forensics Windows Search Cache Parser
   Author: Derek Chadwick
   Date  : 02/03/2014

   Purpose: FineLine global definitions.

*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

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
#define FL_INDEX_IN  0x04
#define FL_CACHE_IN  0x08
#define FL_FILTER_ON 0x10

#define FL_FILE_ACCESS_TIME   0x01
#define FL_FILE_CREATION_TIME 0x02
#define FL_FILE_MODIFY_TIME   0x04

#define DATABASE_FILE_EXT ".txt"
#define EVENT_FILE_EXT ".fle"
#define FL_SEARCH_FILTER_LIST "fl-file-filter-list.txt"
#define WINDOWS_SEARCH_CACHE_FILE "windows.edb"

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

struct fl_file_record
{
   int id;
   long creation_time;
   long access_time;
   long modification_time;
   int access_count;
   char file_access_time_string[32];
   char file_creation_time_string[32];
   char file_modification_time_string[32];
   char file_owner[256];
   char file_name[256];
   char file_path[FL_MAX_INPUT_STR];
   char file_event_string[FL_MAX_INPUT_STR];
};

typedef struct fl_file_record fl_file_record_t;

struct fl_file_filter
{
   int file_id;
   char file_string[FL_MAX_INPUT_STR];
};

typedef struct fl_file_filter fl_file_filter_t;


/*
   ENUMs
*/

enum op_modes { FL_DB_MODE = 1, FL_DB_MODE_X, FL_GUI_MODE, FL_GUI_MODE_X, FL_GUI_AND_DB_MODE, FL_GUI_AND_DB_MODE_X };
enum error_codes { SUCCESS, FILE_ERROR, INTEGRITY_ERROR, MALLOC_ERROR, SYSTEM_ERROR, UNKNOWN_ANOMALY };
enum log_modes { LOG_ERROR, LOG_WARNING, LOG_INFO };

/*
   Function Prototypes
*/

/* fineline-ws.c */
int parse_command_line_args(int argc, char *argv[], char *fl_filename, char *in_file, char *gui_ip_address, char *filter_filename);


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



/* flfilterhashmap.c */

int load_file_filters(char *filter_filename);
struct fl_file_filter *find_filter(int fid);
void add_filter(int fid, struct fl_file_filter *flf);
int match_file_filter(char *file_string);

/* flfilehashmap.c */

void add_file_record(long fid, struct fl_file_record *flf);
struct fl_file_record *find_file(long fid);
void write_file_map(FILE *outfile);
void write_file_map_in_time_sequence(FILE *outfile, int lowest);
void send_file_map();
void send_file_map_in_time_sequence(int lowest);
int time_sort(struct fl_file_record *a, struct fl_file_record *b);
void sort_by_time();
void sort_by_record_number();
void delete_event(struct fl_file_record *file_record);
void delete_all();
struct fl_file_record *get_first_file_record();
struct fl_file_record *get_last_file_record();
long get_first_record_number();

/* flsocket.c */

int init_socket(char *gui_ip_address);
int send_event(char *event_string);
char *get_response();
int close_socket();


