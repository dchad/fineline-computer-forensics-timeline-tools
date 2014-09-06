/*  Copyright 2014 Derek Chadwick

    This file is part of the Fineline Computer Forensics Timeline Tools.

    Fineline is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Fineline is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Fineline.  If not, see <http://www.gnu.org/licenses/>.
*/


/*
   fineline_sensor.h

   Title : Fineline Computer Forensics Utilities
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Fineline global definitions.

*/


/*
   Constant Definitions
*/

#ifndef FINELINE_SENSOR_H
#define FINELINE_SENSOR_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <pcap.h>

#include "uthash.h"

/* structs and types */

struct fl_url_record
{
   char url_record_string[FL_MAX_INPUT_STR];
   double url_time;
   long access_count;
   char url_time_string[32];
   UT_hash_handle hh;
};

typedef struct fl_url_record fl_url_record_t;

struct fl_ip_record
{
   char key_value[512];
   long packet_count;
   long data_size;
   UT_hash_handle hh;
};

typedef struct fl_ip_record fl_ip_record_t;


/* fineline-sensor.c */

int parse_command_line_args(int argc, char *argv[], char *capture_device, char *event_filename, char *server_ip_address, char *filter_file);
int show_sensor_help();

/* flsniffer.c */

pcap_t* open_pcap_socket(char* device, const char* bpfstr);
void start_capture_loop(int packets, pcap_handler func);
void process_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
void terminate_capture(int signal_number);
int start_capture(char *interface, const char *bpf_string, char *event_file, char *server_address, int mode);

/* flfilter.c */

int load_bpf_filters(char *filter_filename, char *filter_string);

/* flurlmap.c */

void add_url(fl_url_record_t *flurl);
fl_url_record_t *find_url(char *lookup_string);
void write_url_map(FILE *outfile);
void send_url_map();
void delete_url(fl_url_record_t *url_record);
void delete_all_urls();
fl_url_record_t *get_first_url_record();
fl_url_record_t *get_last_url_record();

/* flipmap.c */

void add_ip(fl_ip_record_t *flip);
fl_ip_record_t *find_ip(char *lookup_string);
void write_ip_map(FILE *outfile);
void send_ip_map();
void print_ip_map();
void delete_ip(fl_ip_record_t *ip_record);
void delete_all_ips();
fl_ip_record_t *get_first_ip_record();
fl_ip_record_t *get_last_ip_record();

/* fltail.c */

int open_tail_pipe(char *log_file_name);
int start_tail(int fineline_options, int log_option);
int follow_tail();

/* fleventfile.c */

FILE *open_fineline_event_file(char *evt_file_name);
int write_fineline_event_record(char *estr);
int write_fineline_project_header(char *pstr);
int close_fineline_event_file();
int dump_statistics();
int write_event_record(char *event_string);
int create_event_record(char *event_string, char *data_string);




#endif
