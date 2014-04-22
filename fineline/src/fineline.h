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

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 22/12/2013

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

#define LIBEVTX_DLL_IMPORT
#define LIBEVT_DLL_IMPORT

#endif

#define HAVE_LOCAL_LIBCERROR
#define HAVE_LOCAL_LIBCSTRING
#define HAVE_LOCAL_LIBFDATETIME

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <libevtx.h>
#include <libevt.h>

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
#define FL_EVTX_IN   0x04
#define FL_EVT_IN    0x08
#define FL_FILTER_ON 0x10

#define DATABASE_FILE_EXT ".txt"
#define EVENT_FILE_EXT ".fle"
#define WINDOWS_EVENT_LIST "fl-windows-security-event-list.txt"
#define FL_FILTER_LIST "fl-filter-list.txt"

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
#else
#define PATH_SEPARATOR "\\"
#define CURRENT_DIR ".\\"
#define CONFIG_FILE ".\\fineline.conf"
#define LOG_FILE ".\\fineline.log"
#define DATABASE_FILE "fineline-events"
#define EVENT_FILE "fineline-events"
#define EVENT_LOG_PATH "C:\\Windows\\System32\\winevt\\Logs"
#define SYSTEM_LOG_FILE "System.evtx"
#define SECURITY_LOG_FILE "Security.evtx"
#define APPLICATION_LOG_FILE "Application.evtx"
#endif /* LINUX_BUILD */

/*
   REGEXs
*/

#define BEST_REGEX "/^.*(?=.{6,})(?=.*[A-Z])(?=.*[\d])(?=.*[\W]).*$/"
#define STRONG_REGEX "/^[a-zA-Z\d\W_]*(?=[a-zA-Z\d\W_]{6,})(((?=[a-zA-Z\d\W_]*[A-Z])(?=[a-zA-Z\d\W_]*[\d]))|((?=[a-zA-Z\d\W_]*[A-Z])(?=[a-zA-Z\d\W_]*[\W_]))|((?=[a-zA-Z\d\W_]*[\d])(?=[a-zA-Z\d\W_]*[\W_])))[a-zA-Z\d\W_]*$/"
#define WEAK_REGEX "/^[a-zA-Z\d\W_]*(?=[a-zA-Z\d\W_]{6,})(?=[a-zA-Z\d\W_]*[A-Z]|[a-zA-Z\d\W_]*[\d]|[a-zA-Z\d\W_]*[\W_])[a-zA-Z\d\W_]*$/"
#define BAD_REGEX "/^((^[a-z]{6,}$)|(^[A-Z]{6,}$)|(^[\\d]{6,}$)|(^[\\W_]{6,}$))$/"

/*
STRUCTS - Windows event log data structures
*/


/* structure for handling evtx event files */

typedef struct evtx_file evtx_file_t;

struct evtx_file
{
	libevtx_file_t *input_file;
	/* message_handle_t *message_handle; */
	int event_log_type;
	int use_template_definition;
	int input_is_open;
	int ascii_codepage;
	int abort;
};

/* structure for handling evt event files */

typedef struct evt_file evt_file_t;

struct evt_file
{
	/* libevt_file_t *input_file; */
	/* message_handle_t *message_handle; */
	int event_log_type;
	int use_template_definition;
	int input_is_open;
	int ascii_codepage;
	int abort;
};

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

struct fl_event_record
{
   uint64_t id;
   double event_time;
   char event_time_string[32];
   char event_record_string[FL_MAX_INPUT_STR];
   UT_hash_handle hh;
};

typedef struct fl_event_record fl_event_record_t;

struct fl_windows_event_id
{
   int id;
   char *event_id_string;
   char *event_description;
   int year;
   int month;
   int day;
   int hour;
   int minute;
   int second;
   int filter_out;
	UT_hash_handle hh;
};

typedef struct fl_windows_event_id fl_windows_event_id_t;

struct fl_event_filter
{
   int event_id;
   int filter_out;
   UT_hash_handle hh;
};

typedef struct fl_event_filter fl_event_filter_t;


/*
   ENUMs
*/

enum op_modes { FL_DB_MODE = 1, FL_DB_MODE_X, FL_GUI_MODE, FL_GUI_MODE_X, FL_GUI_AND_DB_MODE, FL_GUI_AND_DB_MODE_X };
enum error_codes { SUCCESS, FILE_ERROR, INTEGRITY_ERROR, MALLOC_ERROR, SYSTEM_ERROR, UNKNOWN_ANOMALY };
enum log_modes { LOG_ERROR, LOG_WARNING, LOG_INFO };

/*
   Function Prototypes
*/

/* fineline.c */
int parse_command_line_args(int argc, char *argv[], char *fl_event_filename, char *in_file, char *gui_ip_address, char *filter_filename);

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
/* int print_log_entry(char *estr, FILE *log_file); */
int print_log_entry(char *estr);
int close_log_file();

/* fleventparser.c */
int parse_evtx_event_log(char *evtx_file, char *fl_event_file, int mode, char *gui_ip_addr, char *filter_filename);
int parse_evt_event_log(char *evt_file, char *fl_event_file, int mode, char *gui_ip_addr, char *filter_filename);

/* DEPRECATED in favour of libevt/libevtx
int parse_event_log(FILE *event_file, FILE *log_file);
int extract_system_event_records(FILE *sys_log, FILE *log_file);
int extract_security_event_records(FILE *sec_log, FILE *log_file);
int extract_application_event_records(FILE *app_log, FILE *log_file);
int read_event_log_header(FILE *event_file, FILE *db_file, FILE *log_file);
*/

/* flevtx.c */
int evtx_file_initialise(libevtx_file_t **evtxf);
int evtx_file_open(libevtx_file_t *evtxf, char* filename);
int evtx_process_file(libevtx_file_t *evtxf, char *fl_event_filename, int mode, char *gui_addr);
int evtx_file_close(libevtx_file_t *evtxf);
int evtx_file_free(libevtx_file_t **evtxf);
int evtx_parse_event_record(libevtx_record_t *record, struct fl_event_record *fler, int mode, char *current_id, char *current_time);
const char *get_event_level_text(int event_level );
int filter_duplicate_events(char *current_id, char *current_time, char *prev_id, char *prev_time);
int evtx_get_date_time_string(libevtx_record_t *record, uint64_t *time_val, char *date_time_string);
int evtx_get_message_strings(libevtx_record_t *record, char *mess_string);

/* flevt.c TODO: add libevt parameters */

int evt_file_initialise(libevt_file_t **evtf);
int evt_file_open(libevt_file_t *evtf, char* filename);
int evt_process_file(libevt_file_t *evtf, char *fl_event_filename, int mode, char *gui_addr);
int evt_file_close(libevt_file_t *evtf);
int evt_file_free(libevt_file_t **evtf);
int evt_parse_event_record(libevt_record_t *record, struct fl_event_record *fler, int mode, char *current_id, char *current_time);

int evt_get_date_time_string(libevt_record_t *record, uint64_t *time_val, char *date_time_string);
int evt_get_message_strings(libevt_record_t *record, char *mess_string);

/* flhashmap.c */

void add_windows_event_id(int event_id, char *id_string, char *description);
struct fl_windows_event_id *find_windows_event_id(int event_id);
void delete_windows_event_id(struct fl_windows_event_id *event_record);
void delete_all_ids();
void set_all_event_filters(int filter_val);
void print_windows_event_ids();
int load_windows_event_id_hashmap();

/* flfiltermap.c */

int load_event_filters(char *filter_filename);
struct fl_event_filter *find_filter(int event_id);
void add_filter(int event_id, struct fl_event_filter *flef);

/* fleventhashmap.c */

void add_event_record(uint64_t event_id, struct fl_event_record *fler);
struct fl_event_record *find_event(uint64_t event_id);
void write_event_map(FILE *outfile);
void write_event_map_in_time_sequence(FILE *outfile, uint64_t lowest);
void send_event_map();
void send_event_map_in_time_sequence(uint64_t lowest);
int time_sort(struct fl_event_record *a, struct fl_event_record *b);
void sort_by_time();
void sort_by_record_number();
void delete_event(struct fl_event_record *event_record);
void delete_all();
struct fl_event_record *get_first_event_record();
struct fl_event_record *get_last_event_record();
uint64_t get_first_record_number();

/* flsocket.c */

int init_socket(char *gui_ip_address);
int send_event(char *event_string);
char *get_response();
int close_socket();

/* TODO: */


/* Unit Test Functions */
int unit_tests(FILE *log_file);



