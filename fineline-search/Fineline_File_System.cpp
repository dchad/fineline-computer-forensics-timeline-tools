
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

#include <vector>

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


Fineline_Log *flog = NULL;
Fineline_File_System_Tree *file_system_tree = NULL;
TskImgInfo *image_info = NULL;
Fineline_Progress_Dialog *progress_dialog = NULL;
vector<string> *directory_contents = NULL;
int running = 0;
long directory_count = 0;
long file_count = 0;

/* Static C callback functions for the TSK library calls */

static uint8_t process_file(TskFsFile * fs_file, string filename, string path)
{
   string full_file_path = path;
   fl_file_record_t *frec = (fl_file_record_t *)Fineline_Util::xcalloc(sizeof(fl_file_record_t));
   int file_name_length = filename.size();
   TskFsMeta *fs_meta = fs_file->getMeta();

   strncpy(frec->file_name, filename.c_str(), file_name_length);
   strncpy(frec->file_path, path.c_str(), path.size());

   //if ((file_name_length < 3) && (frec->file_name[0] == '.'))
   //{
	//   Fineline_Util::xfree((char*)frec, sizeof(fl_file_record_t));
	//   return(0);
   //}

   frec->id = file_count++;
   frec->file_size = (long)fs_meta->getSize();
   frec->access_time = (long)fs_meta->getATime();
   frec->creation_time = (long)fs_meta->getCrTime();
   frec->modification_time = (long)fs_meta->getMTime();
   frec->file_type = (int)fs_meta->getType();

   full_file_path.append(frec->file_name);

   if (DEBUG)
      fprintf(stdout, "Fineline_File_System::process_file() <INFO> file name: %s\n", full_file_path.c_str());

   Fl::lock();

   file_system_tree->add_file(full_file_path.c_str(), frec);

   Fl::awake(file_system_tree); //TODO: is this necessary?
   Fl::unlock();

   

   return(0);
}

static TSK_WALK_RET_ENUM process_directory_callback(TskFsFile * fs_file, const char *path, void *ptr)
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
      Fl::lock();
      progress_dialog->add_update(msg);
      Fl::unlock();
      directory_count++;
   }
   fullpath.append(path);
   process_file(fs_file, filename, fullpath);

   return(TSK_WALK_CONT);
}

static uint8_t process_file_system(TskImgInfo * img_info, TSK_OFF_T start)
{
   TskFsInfo *fs_info = new TskFsInfo();
   string msg;
   char number[256];
   int ret_val = 0;

    /* Try it as a file system */
   if (fs_info->open(img_info, start, TSK_FS_TYPE_DETECT))
   {
        tsk_error_print(stderr);
        /* We could do some carving on the volume data at this point */
        ret_val = -1;
   }
   else
   {
      /* Walk the directory structure, starting at the root directory */
      if (fs_info->dirWalk(fs_info->getRootINum(), (TSK_FS_DIR_WALK_FLAG_ENUM) (TSK_FS_DIR_WALK_FLAG_RECURSE), process_directory_callback, NULL))
      {
        tsk_error_print(stderr);
        ret_val = -1;
      }
      fs_info->close();
   }

   delete fs_info;


   msg.append("-------------------------------------------");
   Fl::lock();
   progress_dialog->add_update(msg);
   Fl::unlock();
   msg.clear();
   msg.append("Processed ");
   msg.append(Fineline_Util::xitoa(directory_count, number, 256, 10));
   msg.append(" directories.\n");
   Fl::lock();
   progress_dialog->add_update(msg);
   Fl::unlock();
   msg.clear();
   msg.append("Processed ");
   msg.append(Fineline_Util::xitoa(file_count, number, 256, 10));
   msg.append(" files.\n");
   Fl::lock();
   progress_dialog->add_update(msg);
   Fl::unlock();
   msg.clear();
   msg.append("-------------------------------------------");
   Fl::lock();
   progress_dialog->add_update(msg);
   Fl::unlock();

   return(ret_val);
}

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

static uint8_t process_volume_system(TskImgInfo * img_info, TSK_OFF_T start)
{
   TskVsInfo *vs_info = new TskVsInfo();
   int ret_val = 0;
    // USE mm_walk to get the volumes
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
void* fs_thread_task(void* p)
{
   Fineline_File_System *file_system_image = (Fineline_File_System *)p;
   char msg[256];

   sprintf(msg, "fs_thread_task() <INFO> Start forensic image processing thread: %s\n", file_system_image->get_image_name());
   flog->print_log_entry(msg);

   if (file_system_image->open_forensic_image() == -1)
   {
      flog->print_log_entry("fs_thread_task() <ERROR> Could not open forensic image.\n");
      return(NULL);
   }

   file_system_image->process_forensic_image();

   //Completed parsing the image so notify the GUI
   file_system_tree->rebuild_tree();

   return(NULL);
}




/* Class method implementation */




Fineline_File_System::Fineline_File_System(Fineline_File_System_Tree *ffst, string image_path, Fineline_Progress_Dialog *fpd, Fineline_Log *log)
{
   flog = log;
   file_system_tree = ffst;
   fs_image = image_path;
   progress_dialog = fpd;
   directory_contents = new vector<string>;
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

   update_msg.append("Fineline_File_System::open_forensic_image() <INFO> Opened image:");
   update_msg.append(fs_image);

   flog->print_log_entry(update_msg.c_str());

   itype = image_info->getType();
   update_msg.clear();
   update_msg.append("Processing image type: ");
   update_msg.append(image_info->typeToDesc(itype));

   progress_dialog->add_update(update_msg);

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

void Fineline_File_System::export_file(string file_path, string evidence_directory)
{
   char msg[256];
   //TODO: read int the content of the selected file and write out the file to the evidence directory.
   sprintf(msg, "Fineline_File_System::export_file() <INFO> exporting file %s %s\n", evidence_directory.c_str(), file_path.c_str());
   flog->print_log_entry(msg);
   return;
}

void Fineline_File_System::get_directory_contents(string path)
{
   //TODO: get a vector of fl_file_records for the directory.
   // DEPRECATED: search the existing file records in the file_sytem_tree map.

   return;
}

int Fineline_File_System::get_running()
{
	return(running);
}

const char *Fineline_File_System::get_image_name()
{
   return(fs_image.c_str());
}

void add_progress_text(char *msg)
{
   //TODO: put text to progress dialog
   return;
}



