
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

   Notes: EXPERIMENTAL

*/

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

/* Static C callback functions for the TSK library calls */
static Fineline_Log *flog = NULL;
static Fl_Browser *event_browser = NULL;
static Fineline_File_System_Tree *file_system_tree = NULL;
static TskImgInfo *image_info = NULL;
static Fineline_Util flut;
static int running = 0;

static TSK_WALK_RET_ENUM file_callback(TskFsFile * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr, char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    TSK_MD5_CTX *md = (TSK_MD5_CTX *) ptr;
    if (md == NULL)
        return TSK_WALK_CONT;

    TSK_MD5_Update(md, (unsigned char *) buf, (unsigned int) size);

    return TSK_WALK_CONT;
}

static uint8_t process_file(TskFsFile * fs_file, const char *path)
{
   fl_file_record_t *frec = (fl_file_record_t *)flut.xcalloc(sizeof(fl_file_record_t));
   frec->file_size = fs_file->getMeta()->getSize();
   frec->access_time = fs_file->getMeta()->getATime();
   frec->creation_time = fs_file->getMeta()->getCrTime();
   strncpy(frec->file_name, fs_file->getName()->getName(), strlen(fs_file->getName()->getName()));
   fprintf(stdout, "Fineline_File_System::process_file() <INFO> file name: %s\n", frec->file_name);

   Fl::lock();

      //do some GUI updates here...
   file_system_tree->add_file(fs_file->getName()->getName(), frec);

   Fl::awake(event_browser); //TODO: is this necessary?
   Fl::unlock();


   return(0);
}

static TSK_WALK_RET_ENUM process_directory_callback(TskFsFile * fs_file, const char *path, void *ptr)
{

    /* Ignore NTFS System files */
   if ((TSK_FS_TYPE_ISNTFS(fs_file->getFsInfo()->getFsType())) && (fs_file->getName()->getName()[0] == '$'))
   {
      return TSK_WALK_CONT;
   }
    /* If the name has corresponding metadata, then walk it */
   if (fs_file->getMeta())
   {
      process_file(fs_file, path);
   }

   return TSK_WALK_CONT;
}

static uint8_t process_file_system(TskImgInfo * img_info, TSK_OFF_T start)
{
   TskFsInfo *fs_info = new TskFsInfo();
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
   Input   : Pointer to the Fineline_File_System object.
   Output  : Adds events to the GUI widget.
*/
void* fs_thread_task(void* p)
{
   Fineline_File_System *file_system_image = (Fineline_File_System *)p;
   char msg[256];

   sprintf(msg, "fs_thread_task() <INFO> Start forensic image processing thread: %s\n", file_system_image->get_image_name());
   flog->print_log_entry(msg);

   file_system_image->open_forensic_image();
   file_system_image->process_forensic_image();
   file_system_image->close_forensic_image();

   return(0);
}




/* Class method implementation */




Fineline_File_System::Fineline_File_System(Fineline_File_System_Tree *ffst, string image_path, Fineline_Log *log)
{
   flog = log;
   file_system_tree = ffst;
   fs_image = image_path;
}

Fineline_File_System::~Fineline_File_System()
{
   //dtor
}

int Fineline_File_System::open_forensic_image()
{
   char msg[256];
   image_info = new TskImgInfo();

   if (image_info->open(fs_image.c_str(), TSK_IMG_TYPE_DETECT, 0) == 1)
   {
      delete image_info;
      flog->print_log_entry("open_forensic_image() <ERROR> Could not open image file.\n");
      return(-1);
   }

   sprintf(msg, "Fineline_File_System::open_forensic_image() <INFO> Opened image: %s\n", fs_image.c_str());
   flog->print_log_entry(msg);

   return(0);
}

int Fineline_File_System::process_forensic_image()
{
   if (process_volume_system(image_info, 0))
   {
      delete image_info;
      flog->print_log_entry("process_forensic_image() <ERROR> Could not process image file.\n");
      return(-1);
   }

   return(0);
}

int Fineline_File_System::close_forensic_image()
{
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

int Fineline_File_System::get_running()
{
	return(running);
}

const char *Fineline_File_System::get_image_name()
{
   return(fs_image.c_str());
}





