
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
   Fineline_File_System.cpp

   Title : FineLine Computer Forensics Tools
   Author: Derek Chadwick
   Date  : 28/04/2014

   Purpose: Class implementation for a file system class that uses the Sleuth Kit library to analyse disk images.

            The process consists of:
            open image -> analyse volume system -> analyse file system -> analyse directory -> analyse file

            The process can be run in a thread if the forensic image is very large.

   Notes: EXPERIMENTAL

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>


#ifdef LINUX_BUILD
#include <sys/stat.h>
#else
#include <direct.h> // Windows _mkdir()
#endif



#include "fineline-search.h"
#include "Fineline_File_System.h"
#include "../common/Fineline_Util.h"
#include "../common/threads.h"

#ifdef LINUX_BUILD
#include <unistd.h>
#define FINELINE_SLEEP(delay) usleep(delay*1000);
#else
#define FINELINE_SLEEP(delay) Sleep(delay);
#endif

using namespace std;

Fineline_Log *flog = NULL;
Fineline_File_System_Tree *file_system_tree = NULL;
Fineline_Progress_Dialog *progress_dialog = NULL;
TskImgInfo *image_info = NULL;                 // Store the forensic image system metadata
vector< TskFsInfo * > file_system_list; // List of file systems in the forensic image

int running = 0;
long directory_count = 0;
long file_count = 0;
int file_system_number = 0;
char file_system_label[256];

/* Static C callback functions for the TSK library calls */

static void progress_message(const char *msg_str)
{
   string msg(msg_str);
   Fl::lock();
   progress_dialog->add_progress_message(msg);
   Fl::unlock();
   return;
}

static void put_progress_message(string msg)
{
   Fl::lock();
   progress_dialog->add_progress_message(msg);
   Fl::unlock();
   return;
}

/*
static void check_path_separators(TskFsInfo *fs_info, string full_path)
{
   unsigned int i;

   // Check the forensic image file system type for NTFS/FAT and convert
   // path separators to backslashes since the file system tree widget
   // always uses forward slash.

   if (TSK_FS_TYPE_ISNTFS(fs_info->getFsType()))
   {
      for (i = 0; i < full_path.size(); i++)
      {
         if (full_path[i] == '/')
            full_path[i] = '\\';
      }
   }
   return;
}
*/

/*
   Function: process_file
   Purpose : Called from the process_directory_callback for each file in a directory to
             get the file metadata. Then the file metadata record is added to the
             GUI file system tree.
   Input   : file pointer, file name and file path.
   Output  : Always returns 0 to ensure all files are processed.
*/
static uint8_t process_file(TskFsFile *fs_file, string filename, string path)
{
   fl_file_record_t *frec = (fl_file_record_t *)Fineline_Util::xcalloc(sizeof(fl_file_record_t));
   TskFsMeta *fs_meta = fs_file->getMeta();

   strncpy(frec->file_name, filename.c_str(), filename.size());
   strncpy(frec->file_path, path.c_str(), path.size());
   strncpy(frec->full_path, file_system_label, strlen(file_system_label));  // The full path includes the file system label since
   strncat(frec->full_path, path.c_str(), path.size()); // a multi-volume image will contain multiple file systems.

   frec->id = file_count++;
   frec->marked = 0;
   frec->hidden = 0;
   frec->file_size = (long)fs_meta->getSize();
   frec->access_time = (long)fs_meta->getATime();
   frec->creation_time = (long)fs_meta->getCrTime();
   frec->modification_time = (long)fs_meta->getMTime();
   frec->file_type = (int)fs_meta->getType();

   if (DEBUG)
      printf("Fineline_File_System::process_file() <INFO> file name: %s\n", frec->full_path);

   Fl::lock();

   file_system_tree->add_file(frec->full_path, frec);

   Fl::awake(); //TODO: is this necessary?
   Fl::unlock();

   return(0);
}


/*
   Function: process_directory_callback
   Purpose : Called from the directory walker for each file in a directory, updates
             the progress dialog and calls process_file to get the file metadata.
   Input   : file pointer and file path.
   Output  : Always returns TSK_WALK_CONT to ensure all files are processed.
*/
static TSK_WALK_RET_ENUM process_directory_callback(TskFsFile *fs_file, const char *path, void *ptr)
{

   /* TODO: Ignore winsxs System backup files */
   //if ((TSK_FS_TYPE_ISNTFS(fs_file->getFsInfo()->getFsType())) && (strstr(path, "winsxs") != NULL))
   //{
   //   return TSK_WALK_CONT;
   //}

   /* If the name has corresponding metadata, then walk it */
   string filename;
   string fullpath;
   string msg;
   TskFsMeta *fs_meta = fs_file->getMeta();

   if (fs_meta == NULL)
   {
      return(TSK_WALK_CONT);
   }

   filename.append(fs_file->getName()->getName());

   if (fs_meta->getType() == TSK_FS_META_TYPE_DIR)
   {
      if ((filename.size() < 3) && (filename[0] == '.')) //ignore directory entries
      {
         return(TSK_WALK_CONT);
      }
      msg.append("Processing directory: ");
      msg.append(path);
      msg.append(filename);
      put_progress_message(msg);
      directory_count++;
   }
   fullpath.append(path);
   process_file(fs_file, filename, fullpath);

   return(TSK_WALK_CONT);
}


/*
   Function: process_file_system
   Purpose : Called from the volume walker to process each file system. Does a directory
             walk through the file system and calls process_directory callback for each
             directory found.
   Input   : Forensic image info and offset = 0 for this application.
   Output  : Returns -1 on error, 0 if success.
*/
static uint8_t process_file_system(TskImgInfo * img_info, TSK_OFF_T start)
{
   TskFsInfo *fs_info = new TskFsInfo();
   string msg;
   char number_str[256];

    /* Try it as a file system */
   if (fs_info->open(img_info, start, TSK_FS_TYPE_DETECT))
   {
      progress_message("<ERROR> Opening file system.");
      return(-1);
   }
   else
   {
      /* Create the file system label then walk the directory structure, starting at the root directory */
      memset((void *)file_system_label, 0, 256);
      memset((void *)number_str, 0, 256);
      file_system_number++;
      Fineline_Util::xitoa(file_system_number, number_str, 256, 10);
      strncpy(file_system_label, "FS", 2);
      strncat(file_system_label, number_str, strlen(number_str));
      strncat(file_system_label, "/", 1);


      if (fs_info->dirWalk(fs_info->getRootINum(), (TSK_FS_DIR_WALK_FLAG_ENUM) (TSK_FS_DIR_WALK_FLAG_RECURSE), process_directory_callback, NULL))
      {
         progress_message("<ERROR> Could not walk file system.");
         return(-1);
      }

   }

   // If the file system walk is ok then save the file system info in a vector
   // for later file viewing/extraction by the user.
   file_system_list.push_back(fs_info);

   msg = "-----------------------------------------------------------------------------------";
   put_progress_message(msg);
   msg = "Processed ";
   msg.append(Fineline_Util::xitoa(directory_count, number_str, 256, 10));
   msg.append(" directories.\n");
   put_progress_message(msg);
   msg = "Processed ";
   msg.append(Fineline_Util::xitoa(file_count, number_str, 256, 10));
   msg.append(" files.\n");
   put_progress_message(msg);
   msg = "-----------------------------------------------------------------------------------";
   put_progress_message(msg);

   Fl::awake();

   return(0);
}


/*
   Function: volume_system_callback
   Purpose : Calls process_file_system from the volume walker.
   Input   : Volume and partitions information pointers and user data pointer = NULL for this application.
   Output  : Always returns TSK_WALK_CONT to ensure all partitions are processed.
*/
static TSK_WALK_RET_ENUM volume_system_callback(TskVsInfo * vs_info, const TskVsPartInfo * vs_part, void *ptr)
{
    if (process_file_system(const_cast<TskImgInfo *>(vs_info->getImgInfo()), const_cast<TskVsPartInfo *>(vs_part)->getStart() * vs_info->getBlockSize()))
    {
        // if we return ERROR here, then the walk will stop.  But, the
        // error could just be because we looked into an unallocated volume.
        tsk_error_reset();
    }

    return TSK_WALK_CONT;
}


/*
   Function: process_volume_system
   Purpose : Does a partition walk throught the forensic image and
             calls process_file_system for any file systems found.
   Input   : Image information pointer and start offset = 0.
   Output  : Retruns 0 if OK, -1 on error.
*/
static uint8_t process_volume_system(TskImgInfo * img_info, TSK_OFF_T start)
{
   TskVsInfo *vs_info = new TskVsInfo();
   int ret_val = 0;

   if (vs_info->open(img_info, start, TSK_VS_TYPE_DETECT))
   {
        /* There was no volume system, but there could be a file system */
      tsk_error_reset();
      if (process_file_system(img_info, start))
      {
         ret_val = -1;
      }
   }
   else
   {
        /* Walk the allocated volumes (skip metadata and unallocated volumes) */
      if (vs_info->vsPartWalk(0, vs_info->getPartCount() - 1, (TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC), volume_system_callback, NULL))
      {
         ret_val = -1;
      }
    }

    delete vs_info;

    return(ret_val);
}

/*
   Function: thread_task
   Purpose : Worker function for the posix/win32 thread, must be a C function.
   Input   : Pointer to the file system object.
   Output  : Adds events to the file system tree GUI widget.
*/
void *fs_thread_task(void *p)
{
   Fineline_File_System *file_system_image = (Fineline_File_System *)p;
   char msg[256];
   string pmsg;

   sprintf(msg, "fs_thread_task() <INFO> Start forensic image processing thread: %s\n", file_system_image->get_image_name());
   flog->print_log_entry(msg);

   if (file_system_image->open_forensic_image() == -1)
   {
      flog->print_log_entry("fs_thread_task() <ERROR> Could not open forensic image.\n");
      return(NULL);
   }

   file_system_image->process_forensic_image();

   //Completed parsing the image so notify the GUI

   Fl::awake();

   file_system_tree->rebuild_tree();

   pmsg = "-----------------------------------------------------------------------------------";
   put_progress_message(pmsg);
   pmsg = "Completed rebuilding file system tree.";
   put_progress_message(pmsg);
   pmsg = "-----------------------------------------------------------------------------------";
   put_progress_message(pmsg);

   Fl::awake();

   return(NULL);
}




/* Class method implementation */




Fineline_File_System::Fineline_File_System(Fineline_File_System_Tree *ffst, string image_path, Fineline_Progress_Dialog *fpd, Fineline_Log *log)
{
   flog = log;
   file_system_tree = ffst;
   fs_image = image_path;
   progress_dialog = fpd;
}

Fineline_File_System::~Fineline_File_System()
{
   //dtor
}

int Fineline_File_System::open_forensic_image()
{
   string update_msg;
   TSK_IMG_TYPE_ENUM itype;

   image_info = new TskImgInfo();

   if (image_info->open(fs_image.c_str(), TSK_IMG_TYPE_DETECT, 0) == 1)
   {
      delete image_info;
      flog->print_log_entry("Fineline_File_System::open_forensic_image() <ERROR> Could not open image file.\n");
      return(-1);
   }

   update_msg = "Fineline_File_System::open_forensic_image() <INFO> Opened image:";
   update_msg.append(fs_image);

   flog->print_log_entry(update_msg.c_str());

   itype = image_info->getType();
   update_msg = "Processing image type: ";
   update_msg.append(image_info->typeToDesc(itype));

   put_progress_message(update_msg);

   return(0);
}

int Fineline_File_System::process_forensic_image()
{
   if (process_volume_system(image_info, 0) == 1)
   {
      delete image_info;
      flog->print_log_entry("Fineline_File_System::process_forensic_image() <ERROR> Could not process image file.\n");
      return(-1);
   }

   return(0);
}

int Fineline_File_System::close_forensic_image()
{
   //DEPRECATED: not required
   if (image_info != NULL)
      delete image_info;

   return(0);
}

/*
   Function: start_task
   Purpose : Starts the worker function for the posix/win32 thread.
             Recommended method for processing large forensic images.
   Input   : None.
   Output  : None.
*/
void Fineline_File_System::start_task()
{
	running = 1;
	Fl_Thread thread_id;
	fl_create_thread(thread_id, fs_thread_task, (void *)this);
}

void Fineline_File_System::stop_task()
{
	running = 0;
}


/*
   Function: export_file
   Purpose : Opens the requested file in the forensic image and copies the file
             to the specified evidence directory.
   Input   : Request file path and destination evidence directory.
   Output  : The exported file content, return 0 on success, -1 on error.
*/
int Fineline_File_System::export_file(string file_path, string evidence_directory)
{
   TskFsFile *file_info = new TskFsFile();
   char in_buf[FL_MAX_INPUT_STR];
   FILE *out_file = NULL;
   int len = 0;
   int cnt = 0;
   TSK_OFF_T file_size  = 0;
   TSK_OFF_T offset = 0;
   char msg[256];
   unsigned int i;
   string progress_msg;

   sprintf(msg, "Fineline_File_System::export_file() <INFO> exporting file %s <-> %s\n", evidence_directory.c_str(), file_path.c_str());
   flog->print_log_entry(msg);

   for (i = 0; i < file_system_list.size(); i++)
   {
      TskFsInfo *fs_info = file_system_list[i];

      if (file_info->open(fs_info, file_info, file_path.c_str()))
      {
         sprintf(msg, "Fineline_File_System::export_file() <INFO> Could not open file in file system %i\n", i);
         flog->print_log_entry(msg);
         //progress_message(msg);
      }
      else
      {
         sprintf(msg, "Fineline_File_System::export_file() <INFO> Exporting file %s\n", file_path.c_str());
         flog->print_log_entry(msg);

         // destination_file.append(PATH_SEPARATOR);
         // NOTE: do not use PATH_SEPARATOR, libs will automatically convert to
         // to platform specific path separator on Linux or Windows.

         string destination_file = evidence_directory;
         destination_file.append("/");
         destination_file.append(file_path);

         if (make_path(destination_file, 0775) != 0)  // Linux/Unix permissions: (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)
         {
            sprintf(msg, "Fineline_File_System::export_file() <INFO> Could not make subdirectory in %s\n", evidence_directory.c_str());
            flog->print_log_entry(msg);
            //progress_message(msg);
            //return(-1); do not return, directory may already exist, errno checking is unreliable.
         }

         out_file = fopen(destination_file.c_str(), "wb");
         if (out_file == NULL)
         {
            sprintf(msg, "Fineline_File_System::export_file() <ERROR> Could not open file %s\n", destination_file.c_str());
            flog->print_log_entry(msg);
            progress_message(msg);
            return(-1);
         }
         else
         {
            // Now read in the content of the selected file and write out to the file in the evidence directory.

            file_size = file_info->getMeta()->getSize();
            for (offset = 0; offset < file_size; offset += len)
            {
               if (file_size - offset < 2048)
                  len = (size_t) (file_size - offset);
               else
                  len = 2048;

               cnt = file_info->read(offset, in_buf, len, TSK_FS_FILE_READ_FLAG_NONE);
               if (cnt == -1)
               {
                  // could check tsk_errno here for a recovery error (TSK_ERR_FS_RECOVER)
                  if (DEBUG)
                  {
                     sprintf(msg, "Fineline_File_System::export_file() <ERROR> Reading file %s\n", file_path.c_str());
                     flog->print_log_entry(msg);
                  }
                  break;
               }
               else if (cnt != len)
               {
                  if (DEBUG)
                  {
                     sprintf(msg, "Fineline_File_System::export_file() <WARNING> Allocation error in %s\n", file_path.c_str());
                     flog->print_log_entry(msg);
                  }
               }

               fwrite(in_buf, 1, cnt, out_file);

            }
         }
      }
   }

   if (out_file != NULL)
      fclose(out_file);

   delete file_info;

   progress_msg = "Exported file: ";
   progress_msg.append(file_path);
   put_progress_message(progress_msg);

   return(0);
}

/*
   Function: export_files
   Purpose : Opens the requested files in the forensic image and copies the file
             to the specified evidence directory.
   Input   : Request file path and destination evidence directory.
   Output  : The exported file content, return 0 on success, -1 on error.
*/
int Fineline_File_System::export_files(vector<string> flist, string evidence_directory)
{
   //TODO: iterate over vector and call export_file()

   return(0);
}

int Fineline_File_System::get_running()
{
	return(running);
}

const char *Fineline_File_System::get_image_name()
{
   return(fs_image.c_str());
}


/*
   Function: make_path
   Purpose : Makes the required subdirectories in the evidence
             directory to export files into.
   Input   : The file path and file creation mode (mode is only valid for Linux).
   Output  : Returns 0 on success or errno on failure.
*/
int Fineline_File_System::make_path(string s, mode_t mode)
{
   size_t pre = 0, pos;
   string dir;
   int ret_val = 0;
   int path_len = s.size();
   char msg[256];
   char path[FL_MAX_INPUT_STR];

   if (path[path_len] != '/')  // NOTE: do not use PATH_SEPARATOR, libs will automatically convert to required path separator
   {
      if ((pos = s.find_last_of('/')) == string::npos)
      {
         return(ret_val);
      }
      else
      {
         s = s.substr(0, pos + 1);
         sprintf(msg, "Fineline_File_System::make_path() <INFO> Making directory path %s\n", s.c_str());
         flog->print_log_entry(msg);
      }
   }

    while((pos = s.find_first_of('/', pre)) != string::npos)
    {
      dir = s.substr(0, pos++);
      sprintf(msg, "Fineline_File_System::make_path() <INFO> Making directory %s\n", dir.c_str());
      flog->print_log_entry(msg);
      pre = pos;
      if(dir.size() == 0) continue; // if leading / first time is 0 length

#ifdef LINUX_BUILD
      if((ret_val = mkdir(dir.c_str(), mode)) && (errno != EEXIST))
#else
      if((ret_val = _mkdir(dir.c_str())) && (errno != EEXIST))
#endif
      {
         return ret_val;
      }
    }

   return ret_val;
}





