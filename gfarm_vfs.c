/* 
 * Gfarm Samba VFS module.
 * v0.0.1 03 Sep 2010  Hiroki Ohtsuji <ohtsuji at hpcs.cs.tsukuba.ac.jp>
 * 
 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
//#include <stdio.h>

#include "includes.h"
#include <gfarm/gfarm.h>


/* XXX FIXME */
#define GFS_DEV		((dev_t)-1)
#define GFS_BLKSIZE	8192
#define STAT_BLKSIZ	512	/* for st_blocks */


static int
gfs_hook_open_flags_gfarmize(int open_flags)
{
	int gfs_flags;
	switch (open_flags & O_ACCMODE) {
	case O_RDONLY:
		gfs_flags = GFARM_FILE_RDONLY;
		break;
	case O_WRONLY:
		gfs_flags = GFARM_FILE_WRONLY;
		break;
	case O_RDWR:
		gfs_flags = GFARM_FILE_RDWR;
		break;
	default: return (-1);
	}

#if 0 /* this is unnecessary */
	if ((open_flags & O_CREAT) != 0)
		gfs_flags |= GFARM_FILE_CREATE;
#endif
	if ((open_flags & O_TRUNC) != 0)
		gfs_flags |= GFARM_FILE_TRUNC;
#if 0 /* not yet on Gfarm v2 */
	if ((open_flags & O_APPEND) != 0)
		gfs_flags |= GFARM_FILE_APPEND;
	if ((open_flags & O_EXCL) != 0)
		gfs_flags |= GFARM_FILE_EXCLUSIVE;
#endif
#if 0 /* not yet on Gfarm v2 */
	/* open(2) and creat(2) should be unbuffered */
	gfs_flags |= GFARM_FILE_UNBUFFERED;
#endif
	return (gfs_flags);
}


static uid_t
get_uid(char *user)
{
	struct passwd *pwd;
	char *luser;


	if (strcmp(gfarm_get_global_username(), user) == 0)
		return (getuid()); /* my own file */

	/*
	 * XXX - this interface will be changed soon to support
	 * multiple gfmds.
	 */
	if (gfarm_global_to_local_username(user, &luser)
	    == GFARM_ERR_NO_ERROR) {
		pwd = getpwnam(luser);
		free(luser);
		if (pwd != NULL)
			return (pwd->pw_uid);
	}
	/* cannot conver to a local account */
	return (0);
}

static int
get_gid(char *group)
{
	struct group *grp;
	char *lgroup;

	/*
	 * XXX - this interface will be changed soon to support
	 * multiple gfmds.
	 */
	if (gfarm_global_to_local_groupname(group, &lgroup)
	    == GFARM_ERR_NO_ERROR) {
		grp = getgrnam(lgroup);
		free(lgroup);
		if (grp != NULL)
			return (grp->gr_gid);
	}
	/* cannot conver to a local group */
	return (0);
}

static int
get_nlink(struct gfs_stat *st)
{
	/* XXX FIXME */
	return (GFARM_S_ISDIR(st->st_mode) ? 32000 : st->st_nlink);
}



static void
copy_gfs_stat(/*struct stat*/SMB_STRUCT_STAT *dst, struct gfs_stat *src)
{
	memset(dst, 0, sizeof(*dst));
	dst->st_dev = GFS_DEV;
	dst->st_ino = src->st_ino;
	dst->st_mode = src->st_mode;
	dst->st_nlink = get_nlink(src);
	dst->st_uid = get_uid(src->st_user);
	dst->st_gid = get_gid(src->st_group);
	dst->st_size = src->st_size;
	dst->st_blksize = GFS_BLKSIZE;
	dst->st_blocks = (src->st_size + STAT_BLKSIZ - 1) / STAT_BLKSIZ;
	dst->st_atime = src->st_atimespec.tv_sec;
	dst->st_mtime = src->st_mtimespec.tv_sec;
	dst->st_ctime = src->st_ctimespec.tv_sec;
}




static int gfvfs_connect(vfs_handle_struct *handle,  const char *service, const char *user)	
{

	gfarm_error_t e;

	(void) handle;
	(void) service;
	(void) user;
	e = gfarm_initialize(0, NULL);
	if (e != GFARM_ERR_NO_ERROR) {
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return 0;
}

static void gfvfs_disconnect(vfs_handle_struct *handle, connection_struct *conn)
{
	gfarm_error_t e;
	(void) handle;
	(void) conn;
	e = gfarm_terminate();
	if(e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return ;
	}
	return;
}

static SMB_BIG_UINT gfvfs_disk_free(vfs_handle_struct *handle,  const char *path,
	BOOL small_query, SMB_BIG_UINT *bsize,
	SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{

	(void) handle;
	(void) path;
	(void) small_query;
	(void) bsize;
	(void) dfree;
	(void) dsize;
        return 0;
}

static int gfvfs_get_quota(vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dq)
{

	(void) handle;
	(void) qtype;
	(void) id;
	(void) dq;
        return 0;
}

static int gfvfs_set_quota(vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dq)
{

	(void) handle;
	(void) qtype;
	(void) id;
	(void) dq;


	 return 0;
}

static int gfvfs_get_shadow_copy_data(vfs_handle_struct *handle, files_struct *fsp, SHADOW_COPY_DATA *shadow_copy_data, BOOL labels)
{

        return 0;
}

static int gfvfs_statvfs(struct vfs_handle_struct *handle,  const char *path, struct vfs_statvfs_struct *statbuf)
{

	(void) handle;
	(void) path;
	(void) statbuf;
	gfarm_error_t e;
	gfarm_off_t used, avail, files;
	e = gfs_statfs(&used, &avail, &files);
	if (e != GFARM_ERR_NO_ERROR) {
		errno = gfarm_error_to_errno(e);
		return -1;
	} else {
		statbuf->BlockSize = 1024;
		statbuf->TotalBlocks = used + avail;
		statbuf->BlocksAvail = avail;
		statbuf->UserBlocksAvail = avail;
		statbuf->TotalFileNodes = files;
		statbuf->FreeFileNodes = -1;
	}
	return 0;
}

int dof = 0;

static SMB_STRUCT_DIR *gfvfs_opendir(vfs_handle_struct *handle,  const char *fname, const char *mask, uint32 attr)
{

	dof = 0;
	gfarm_error_t e;
	GFS_Dir dp;
	e = gfs_opendir_caching(fname, &dp );
	if (e != GFARM_ERR_NO_ERROR) {
		/*
		gfarm2fs_check_error(2000005, "OPENDIR",
			"gfs_opendir_caching", fname, e);
		*/
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	(void) handle;
	(void) fname;
	(void) mask;
	(void) attr;
	return (SMB_STRUCT_DIR *)dp;
}

static SMB_STRUCT_DIRENT *gfvfs_readdir(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dirp)
{

	GFS_Dir dp = /*get_dirp(fi)*/ (GFS_Dir)dirp;
	struct gfs_dirent *de;
	struct stat st;
	/* gfarm_off_t off = 0; */
	gfarm_error_t e;

	SMB_STRUCT_DIRENT *ssd;
	ssd = (SMB_STRUCT_DIRENT *)malloc(sizeof(SMB_STRUCT_DIRENT));
	if(!ssd){
		write(1,"SSD-NULL",strlen("SSD-NULL"));
	}
	//(void) path;
	/* XXX gfs_seekdir(dp, offset); */
	e = gfs_readdir(dp, &de);
	if (e != GFARM_ERR_NO_ERROR) {
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	if(de!=NULL){

		ssd->d_fileno = de->d_fileno;
		ssd->d_reclen = de->d_reclen;
		ssd->d_type = de->d_type;
		ssd->d_off = 0;
		dof++;
		strncpy( ssd->d_name, de->d_name, /*256*/sizeof(ssd->d_name));
	} else {
		return(NULL);
	}
	return ssd;
}

static void gfvfs_seekdir(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dirp, long offset)
{
	gfarm_error_t e;
	
	GFS_Dir dp = dirp;
	
	e = gfs_seekdir(dp, offset);
	if( e!= GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return ;
	
}


static long gfvfs_telldir(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dirp)
{       
	return 0;

	gfarm_error_t e;
	long off;
	e = gfs_telldir(dirp, &off);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return(off);
}

static void gfvfs_rewinddir(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dirp)
{
	return 0;
}

static int gfvfs_mkdir(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	gfarm_error_t e;
	
	e = gfs_mkdir(path, mode & GFARM_S_ALLPERM);
	if( e!= GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return 0;

}

static int gfvfs_rmdir(vfs_handle_struct *handle,  const char *path)
{
	gfarm_error_t e;

	e = gfs_rmdir(path);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return 0;
}

static int gfvfs_closedir(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dir)
{
	GFS_Dir dp = dir;	//DIR = dirp
	gfarm_error_t e;

	e = gfs_closedir(dp);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return (0);
}

static int gfvfs_open(vfs_handle_struct *handle,  const char *fname, files_struct *fsp, int flags, mode_t mode)
{
#ifdef SDEBUG
        char errtmp[64];
        snprintf(errtmp, sizeof(errtmp), "gf2smb: open=%s",fname);
        write(1, errtmp, strlen(errtmp));
#endif
	GFS_File gf;
	int g_flags;
	char *path;
	path = fname;
	gfarm_error_t e;
	g_flags = gfs_hook_open_flags_gfarmize(flags);
	
	if(flags & O_CREAT){
		e = gfs_pio_create(fname, g_flags, mode & GFARM_S_ALLPERM, &gf);
		if( e!= GFARM_ERR_NO_ERROR){
			errno = gfarm_error_to_errno(e);
			return -1;
		}
		gfs_pio_close(gf);
	}
	e = gfs_pio_open(fname, g_flags, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
        errno = gfarm_error_to_errno(e);
        return -1;
	}
	fsp->fh->file_id = (unsigned long)gf;
	return (0);
}

static int gfvfs_close(vfs_handle_struct *handle, files_struct *fsp, int fd)
{
	gfarm_error_t e;

	e = gfs_pio_close((GFS_File)fsp->fh->file_id);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return (0);
}

static ssize_t gfvfs_read(vfs_handle_struct *handle, files_struct *fsp, int fd, void *data, size_t n)
{
	gfarm_error_t e;
	gfarm_off_t off;
	int rv;

	e = gfs_pio_read((GFS_File)fsp->fh->file_id, (char *)data, n, &rv);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
    return (rv);

}

static ssize_t gfvfs_pread(vfs_handle_struct *handle, struct files_struct *fsp, int fd, void *data, size_t n, SMB_OFF_T offset)
{
	gfarm_error_t e;
	gfarm_off_t off;
	int rv;

	e = gfs_pio_seek((GFS_File)fsp->fh->file_id, (off_t)offset, GFARM_SEEK_SET, &off);	//get_filep(fi)
	if (e != GFARM_ERR_NO_ERROR) {
		errno = gfarm_error_to_errno(e);
		return -1;
	} else {
		e = gfs_pio_read((GFS_File)fsp->fh->file_id, data, n, &rv);
	}
	
	if (e != GFARM_ERR_NO_ERROR){
			errno = gfarm_error_to_errno(e);
			return -1;
			rv = 0;
	}
	
	return (rv);
	
}

static ssize_t gfvfs_write(vfs_handle_struct *handle, files_struct *fsp, int fd, const void *data, size_t n)
{
	gfarm_error_t e;
	int rv;
	e = gfs_pio_write((GFS_File)fsp->fh->file_id, data, n, &rv);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return rv;

}

ssize_t gfvfs_pwrite(vfs_handle_struct *handle, struct files_struct *fsp, int fd, const void *data, size_t n, SMB_OFF_T offset)
{
	gfarm_error_t e;
	gfarm_off_t off;
	int rv;

	e = gfs_pio_seek((GFS_File)fsp->fh->file_id, offset, GFARM_SEEK_SET, &off);

	if (e != GFARM_ERR_NO_ERROR) {
		errno = gfarm_error_to_errno(e);
		return -1;
	} else {
		e = gfs_pio_write((GFS_File)fsp->fh->file_id, data, n, &rv);
	}

	if (e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return (rv);
}

static SMB_OFF_T gfvfs_lseek(vfs_handle_struct *handle, files_struct *fsp, int filedes, SMB_OFF_T offset, int whence)
{
	gfarm_error_t e;
	gfarm_off_t off;
	e = gfs_pio_seek((GFS_File)fsp->fh->file_id, offset, GFARM_SEEK_SET, &off);
	if (e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return off;
}

static int gfvfs_rename(vfs_handle_struct *handle,  const char *oldname, const char *newname)
{
	gfarm_error_t e;
	e = gfs_rename(oldname, newname);
	if (e != GFARM_ERR_NO_ERROR) {
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return 0;
}

static int gfvfs_fsync(vfs_handle_struct *handle, files_struct *fsp, int fd)
{
	(void) handle;
	(void) fd;
	
	gfarm_error_t e;
	e = gfs_pio_sync((GFS_File)fsp->fh->file_id);
	if(e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return 0;
}

static int gfvfs_stat(vfs_handle_struct *handle,  const char *fname, SMB_STRUCT_STAT *sbuf)
{
	struct gfs_stat st;
	gfarm_error_t e;

	e = gfs_stat(fname, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		errno = gfarm_error_to_errno(e);
		return -1;
	}

	copy_gfs_stat(sbuf, &st);
	gfs_stat_free(&st);

	return 0;
}

static int gfvfs_fstat(vfs_handle_struct *handle, files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf)
{
	struct gfs_stat st;
	gfarm_error_t e;

	e = gfs_pio_stat((GFS_File)fsp->fh->file_id, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	copy_gfs_stat(sbuf, &st);
	gfs_stat_free(&st);

        return 0;
}

static int gfvfs_lstat(vfs_handle_struct *handle,  const char *path, SMB_STRUCT_STAT *sbuf)
{
        struct gfs_stat st;
        gfarm_error_t e;
        e = gfs_lstat(path, &st);
        if (e != GFARM_ERR_NO_ERROR) {
			errno = gfarm_error_to_errno(e);
			return -1;
        }
        copy_gfs_stat(sbuf, &st);
        gfs_stat_free(&st);
        return 0;
}

static int gfvfs_unlink(vfs_handle_struct *handle,  const char *path)
{
	gfarm_error_t e;

	e = gfs_unlink(path);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
	return 0;

}

static int gfvfs_chmod(vfs_handle_struct *handle,  const char *path, mode_t mode)
{


	gfarm_error_t e;;
	e = gfs_chmod(path, mode & GFARM_S_ALLPERM);
	if(e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}

        return 0;
}

static int gfvfs_fchmod(vfs_handle_struct *handle, files_struct *fsp, int fd, mode_t mode)
{

	return 0;
}

static int gfvfs_chown(vfs_handle_struct *handle,  const char *path, uid_t uid, gid_t gid)
{

        return 0;
}

static int gfvfs_fchown(vfs_handle_struct *handle, files_struct *fsp, int fd, uid_t uid, gid_t gid)
{

        return 0;
}

static int gfvfs_chdir(vfs_handle_struct *handle,  const char *path)
{

        return 0;
}

static char *gfvfs_getwd(vfs_handle_struct *handle,  char *buf)
{

        return 0;
}

static int gfvfs_ntimes(vfs_handle_struct *handle,  const char *path, const struct timespec ts[2])
{

        return 0;
}

static int gfvfs_ftruncate(vfs_handle_struct *handle, files_struct *fsp, int fd, SMB_OFF_T offset)
{
	gfarm_error_t e;
	e = gfs_pio_truncate((GFS_File)fsp->fh->file_id, /*offset*/0);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}

        return 0;
}

static BOOL gfvfs_lock(vfs_handle_struct *handle, files_struct *fsp, int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type)
{
        return 0;
}

static BOOL gfvfs_getlock(vfs_handle_struct *handle, files_struct *fsp, int fd, SMB_OFF_T *poffset, SMB_OFF_T *pcount, int *ptype, pid_t *ppid)
{
        return 0;
}

static int gfvfs_symlink(vfs_handle_struct *handle,  const char *oldpath, const char *newpath)
{
	gfarm_error_t e;
	e = gfs_symlink(oldpath, newpath);
	if( e != GFARM_ERR_NO_ERROR){
		errno = gfarm_error_to_errno(e);
		return -1;
	}
        return 0;
}


static int gfvfs_readlink(vfs_handle_struct *handle,  const char *path, char *buf, size_t bufsiz)
{
        return 0;
}

static int gfvfs_link(vfs_handle_struct *handle,  const char *oldpath, const char *newpath)
{
        return 0;
}

static int gfvfs_mknod(vfs_handle_struct *handle,  const char *path, mode_t mode, SMB_DEV_T dev)
{
        return 0;
}

static char *gfvfs_realpath(vfs_handle_struct *handle,  const char *path, char *resolved_path)
{
        return 0;
}

static NTSTATUS gfvfs_notify_watch(struct vfs_handle_struct *handle,
		struct sys_notify_context *ctx, struct notify_entry *e,
		void (*callback)(struct sys_notify_context *ctx, void *private_data, struct notify_event *ev),
		void *private_data, void *handle_p)
{


	return NT_STATUS_NOT_SUPPORTED;
}

static int gfvfs_chflags(vfs_handle_struct *handle,  const char *path, uint flags)
{

	return 0;
}

static size_t gfvfs_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
	int fd, uint32 security_info, SEC_DESC **ppdesc)
{
	return 0;
}

static size_t gfvfs_get_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
	const char *name, uint32 security_info, SEC_DESC **ppdesc)
{
	return 0;
}



static BOOL gfvfs_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp, int
	fd, uint32 security_info_sent, SEC_DESC *psd)
{
	return False;
}

static BOOL gfvfs_set_nt_acl(vfs_handle_struct *handle, files_struct *fsp, const
	char *name, uint32 security_info_sent, SEC_DESC *psd)
{
	return False;
}

static int gfvfs_chmod_acl(vfs_handle_struct *handle,  const char *name, mode_t mode)
{
	return 0;
}

static int gfvfs_fchmod_acl(vfs_handle_struct *handle, files_struct *fsp, int fd, mode_t mode)
{
	return 0;
}

static int gfvfs_sys_acl_get_entry(vfs_handle_struct *handle,  SMB_ACL_T theacl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	return 0;
}

static int gfvfs_sys_acl_get_tag_type(vfs_handle_struct *handle,  SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
	return 0;
}

static int gfvfs_sys_acl_get_permset(vfs_handle_struct *handle,  SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{

	return 0;
}

static void *gfvfs_sys_acl_get_qualifier(vfs_handle_struct *handle,  SMB_ACL_ENTRY_T entry_d)
{
	return NULL;
}

static SMB_ACL_T gfvfs_sys_acl_get_file(vfs_handle_struct *handle,  const char *path_p, SMB_ACL_TYPE_T type)
{
	return NULL;
}

static SMB_ACL_T gfvfs_sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp, int fd)
{
	//errno = ENOSYS;
	return NULL;
}

static int gfvfs_sys_acl_clear_perms(vfs_handle_struct *handle,  SMB_ACL_PERMSET_T permset)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_add_perm(vfs_handle_struct *handle,  SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	//errno = ENOSYS;
	return 0;
}

static char *gfvfs_sys_acl_to_text(vfs_handle_struct *handle,  SMB_ACL_T theacl, ssize_t *plen)
{
	//errno = ENOSYS;
	return NULL;
}

static SMB_ACL_T gfvfs_sys_acl_init(vfs_handle_struct *handle,  int count)
{
	//errno = ENOSYS;
	return NULL;
}

static int gfvfs_sys_acl_create_entry(vfs_handle_struct *handle,  SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_set_tag_type(vfs_handle_struct *handle,  SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_set_qualifier(vfs_handle_struct *handle,  SMB_ACL_ENTRY_T entry, void *qual)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_set_permset(vfs_handle_struct *handle,  SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_valid(vfs_handle_struct *handle,  SMB_ACL_T theacl )
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_set_file(vfs_handle_struct *handle,  const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp, int fd, SMB_ACL_T theacl)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_delete_def_file(vfs_handle_struct *handle,  const char *path)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_get_perm(vfs_handle_struct *handle,  SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_free_text(vfs_handle_struct *handle,  char *text)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_free_acl(vfs_handle_struct *handle,  SMB_ACL_T posix_acl)
{
	//errno = ENOSYS;
	return 0;
}

static int gfvfs_sys_acl_free_qualifier(vfs_handle_struct *handle,  void *qualifier, SMB_ACL_TAG_T tagtype)
{
	//errno = ENOSYS;
	return 0;
}

static ssize_t gfvfs_getxattr(vfs_handle_struct *handle, const char *path, const char *name, void *value, size_t size)
{
	return 0;
}

static ssize_t gfvfs_lgetxattr(vfs_handle_struct *handle, const char *path, const char *name, void *value, size_t
size)
{
	return 0;
}

static ssize_t gfvfs_fgetxattr(vfs_handle_struct *handle, struct files_struct *fsp,int fd, const char *name, void *value, size_t size)
{
	return 0;
}

static ssize_t gfvfs_listxattr(vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	return 0;
}

static ssize_t gfvfs_llistxattr(vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	return 0;
}

static ssize_t gfvfs_flistxattr(vfs_handle_struct *handle, struct files_struct *fsp,int fd, char *list, size_t size)
{
	return 0;
}

static int gfvfs_removexattr(vfs_handle_struct *handle, const char *path, const char *name)
{
	return 0;
}

static int gfvfs_lremovexattr(vfs_handle_struct *handle, const char *path, const char *name)
{
	return 0;
}

static int gfvfs_fremovexattr(vfs_handle_struct *handle, struct files_struct *fsp,int fd, const char *name)
{
	return 0;
}

static int gfvfs_setxattr(vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	return 0;
}

static int gfvfs_lsetxattr(vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	return 0;
}

static int gfvfs_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,int fd, const char *name, const void *value, size_t size, int flags)
{
	return 0;
}

static int gfvfs_aio_read(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb)
{
        return 0;
}

static int gfvfs_aio_write(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb)
{

        return 0;
}

static ssize_t gfvfs_aio_return(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb)
{
        return 0;
}

static int gfvfs_aio_cancel(struct vfs_handle_struct *handle, struct files_struct *fsp, int fd, SMB_STRUCT_AIOCB *aiocb)
{
        return 0;
}

static int gfvfs_aio_error(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb)
{

        return 0;
}

static int gfvfs_aio_fsync(struct vfs_handle_struct *handle, struct files_struct *fsp, int op, SMB_STRUCT_AIOCB *aiocb)
{

        return 0;
}

static int gfvfs_aio_suspend(struct vfs_handle_struct *handle, struct files_struct *fsp, const SMB_STRUCT_AIOCB * const aiocb[], int n, const struct timespec *ts)
{

        return 0;
}

/* VFS operations structure */

static vfs_op_tuple gfvfs_op_tuples[] = {

	/* Disk operations */

	{SMB_VFS_OP(gfvfs_connect),			SMB_VFS_OP_CONNECT, 		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_disconnect),			SMB_VFS_OP_DISCONNECT,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_disk_free),			SMB_VFS_OP_DISK_FREE,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_get_quota),			SMB_VFS_OP_GET_QUOTA,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_set_quota),			SMB_VFS_OP_SET_QUOTA,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_get_shadow_copy_data),		SMB_VFS_OP_GET_SHADOW_COPY_DATA,SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_statvfs),			SMB_VFS_OP_STATVFS,		SMB_VFS_LAYER_OPAQUE},

	/* Directory operations */

	{SMB_VFS_OP(gfvfs_opendir),			SMB_VFS_OP_OPENDIR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_readdir),			SMB_VFS_OP_READDIR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_seekdir),			SMB_VFS_OP_SEEKDIR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_telldir),			SMB_VFS_OP_TELLDIR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_rewinddir),			SMB_VFS_OP_REWINDDIR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_mkdir),			SMB_VFS_OP_MKDIR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_rmdir),			SMB_VFS_OP_RMDIR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_closedir),			SMB_VFS_OP_CLOSEDIR,		SMB_VFS_LAYER_OPAQUE},

	/* File operations */

	{SMB_VFS_OP(gfvfs_open),				SMB_VFS_OP_OPEN,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_close),			SMB_VFS_OP_CLOSE,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_read),				SMB_VFS_OP_READ,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_pread),			SMB_VFS_OP_PREAD,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_write),			SMB_VFS_OP_WRITE,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_pwrite),			SMB_VFS_OP_PWRITE,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_lseek),			SMB_VFS_OP_LSEEK,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_rename),			SMB_VFS_OP_RENAME,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fsync),			SMB_VFS_OP_FSYNC,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_stat),				SMB_VFS_OP_STAT,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fstat),			SMB_VFS_OP_FSTAT,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_lstat),			SMB_VFS_OP_LSTAT,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_unlink),			SMB_VFS_OP_UNLINK,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_chmod),			SMB_VFS_OP_CHMOD,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fchmod),			SMB_VFS_OP_FCHMOD,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_chown),			SMB_VFS_OP_CHOWN,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fchown),			SMB_VFS_OP_FCHOWN,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_chdir),			SMB_VFS_OP_CHDIR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_getwd),			SMB_VFS_OP_GETWD,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_ntimes),			SMB_VFS_OP_NTIMES,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_ftruncate),			SMB_VFS_OP_FTRUNCATE,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_lock),				SMB_VFS_OP_LOCK,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_getlock),			SMB_VFS_OP_GETLOCK,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_symlink),			SMB_VFS_OP_SYMLINK,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_readlink),			SMB_VFS_OP_READLINK,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_link),				SMB_VFS_OP_LINK,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_mknod),			SMB_VFS_OP_MKNOD,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_realpath),			SMB_VFS_OP_REALPATH,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_notify_watch),			SMB_VFS_OP_NOTIFY_WATCH,	SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_chflags),			SMB_VFS_OP_CHFLAGS,		SMB_VFS_LAYER_OPAQUE},



	/* NT File ACL operations */

	{SMB_VFS_OP(gfvfs_fget_nt_acl),			SMB_VFS_OP_FGET_NT_ACL,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_get_nt_acl),			SMB_VFS_OP_GET_NT_ACL,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fset_nt_acl),			SMB_VFS_OP_FSET_NT_ACL,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_set_nt_acl),			SMB_VFS_OP_SET_NT_ACL,		SMB_VFS_LAYER_OPAQUE},

	/* POSIX ACL operations */

	{SMB_VFS_OP(gfvfs_chmod_acl),			SMB_VFS_OP_CHMOD_ACL,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fchmod_acl),			SMB_VFS_OP_FCHMOD_ACL,		SMB_VFS_LAYER_OPAQUE},

	{SMB_VFS_OP(gfvfs_sys_acl_get_entry),		SMB_VFS_OP_SYS_ACL_GET_ENTRY,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_get_tag_type),		SMB_VFS_OP_SYS_ACL_GET_TAG_TYPE,	SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_get_permset),		SMB_VFS_OP_SYS_ACL_GET_PERMSET,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_get_qualifier),	SMB_VFS_OP_SYS_ACL_GET_QUALIFIER,	SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_get_file),		SMB_VFS_OP_SYS_ACL_GET_FILE,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_get_fd),		SMB_VFS_OP_SYS_ACL_GET_FD,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_clear_perms),		SMB_VFS_OP_SYS_ACL_CLEAR_PERMS,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_add_perm),		SMB_VFS_OP_SYS_ACL_ADD_PERM,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_to_text),		SMB_VFS_OP_SYS_ACL_TO_TEXT,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_init),			SMB_VFS_OP_SYS_ACL_INIT,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_create_entry),		SMB_VFS_OP_SYS_ACL_CREATE_ENTRY,	SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_set_tag_type),		SMB_VFS_OP_SYS_ACL_SET_TAG_TYPE,	SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_set_qualifier),	SMB_VFS_OP_SYS_ACL_SET_QUALIFIER,	SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_set_permset),		SMB_VFS_OP_SYS_ACL_SET_PERMSET,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_valid),		SMB_VFS_OP_SYS_ACL_VALID,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_set_file),		SMB_VFS_OP_SYS_ACL_SET_FILE,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_set_fd),		SMB_VFS_OP_SYS_ACL_SET_FD,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_delete_def_file),	SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE,	SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_get_perm),		SMB_VFS_OP_SYS_ACL_GET_PERM,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_free_text),		SMB_VFS_OP_SYS_ACL_FREE_TEXT,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_free_acl),		SMB_VFS_OP_SYS_ACL_FREE_ACL,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_sys_acl_free_qualifier),	SMB_VFS_OP_SYS_ACL_FREE_QUALIFIER,	SMB_VFS_LAYER_OPAQUE},
	
	/* EA operations. */
	{SMB_VFS_OP(gfvfs_getxattr),			SMB_VFS_OP_GETXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_lgetxattr),			SMB_VFS_OP_LGETXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fgetxattr),			SMB_VFS_OP_FGETXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_listxattr),			SMB_VFS_OP_LISTXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_llistxattr),			SMB_VFS_OP_LLISTXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_flistxattr),			SMB_VFS_OP_FLISTXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_removexattr),			SMB_VFS_OP_REMOVEXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_lremovexattr),			SMB_VFS_OP_LREMOVEXATTR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fremovexattr),			SMB_VFS_OP_FREMOVEXATTR,		SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_setxattr),			SMB_VFS_OP_SETXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_lsetxattr),			SMB_VFS_OP_LSETXATTR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_fsetxattr),			SMB_VFS_OP_FSETXATTR,			SMB_VFS_LAYER_OPAQUE},

	/* AIO operations. */
	{SMB_VFS_OP(gfvfs_aio_read),			SMB_VFS_OP_AIO_READ,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_aio_write),			SMB_VFS_OP_AIO_WRITE,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_aio_return),			SMB_VFS_OP_AIO_RETURN,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_aio_cancel),			SMB_VFS_OP_AIO_CANCEL,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_aio_error),			SMB_VFS_OP_AIO_ERROR,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_aio_fsync),			SMB_VFS_OP_AIO_FSYNC,			SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(gfvfs_aio_suspend),			SMB_VFS_OP_AIO_SUSPEND,			SMB_VFS_LAYER_OPAQUE},

	{NULL,						SMB_VFS_OP_NOOP,			SMB_VFS_LAYER_NOOP}
};

NTSTATUS init_module(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "gfarm_vfs", gfvfs_op_tuples);
}

