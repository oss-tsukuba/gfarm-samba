/*
 * Gfarm Samba VFS module.
 * v0.0.1 03 Sep 2010  Hiroki Ohtsuji <ohtsuji at hpcs.cs.tsukuba.ac.jp>
 * Copyright (c) 2012 Osamu Tatebe.  All Rights Reserved.
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

/*
 * $Id$
 */

#include "includes.h"
#include "smbd/proto.h"

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#include <gfarm/gfarm.h>

#include "gfarm_acl.h"
#include "gfarm_id.h"

/* internal interface */
int gfs_pio_fileno(GFS_File);
gfarm_error_t gfs_statdir(GFS_Dir, struct gfs_stat *);

/* XXX FIXME */
#define GFS_DEV		((dev_t)-1)
#define GFS_BLKSIZE	8192
#define STAT_BLKSIZ	512	/* for st_blocks */

static void
gfvfs_error(int msgno, const char *func_name, gfarm_error_t e)
{
	if (e == GFARM_ERR_NO_SUCH_FILE_OR_DIRECTORY ||
	    e == GFARM_ERR_NO_SUCH_OBJECT ||
	    e == GFARM_ERR_IS_A_DIRECTORY ||
	    e == GFARM_ERR_ALREADY_EXISTS)
		gflog_debug(msgno, "%s: %s", func_name, gfarm_error_string(e));
	else
		gflog_error(msgno, "%s: %s", func_name, gfarm_error_string(e));
}

static int
open_flags_gfarmize(int open_flags)
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
	default:
		return (-1);
	}
	if ((open_flags & O_TRUNC) != 0)
		gfs_flags |= GFARM_FILE_TRUNC;

	return (gfs_flags);
}

static uid_t
get_uid(const char *path, const char *user)
{
	gfarm_error_t e;
	uid_t uid;

	e = gfarm_id_user_to_uid(path, user, &uid);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_warning(GFARM_MSG_UNFIXED,
		    "get_uid(%s): %s", user, gfarm_error_string(e));
		return (gfarm_id_nobody_uid());
	}
	return (uid);
}

static gid_t
get_gid(const char *path, const char *group)
{
	gfarm_error_t e;
	gid_t gid;

	e = gfarm_id_group_to_gid(path, group, &gid);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_warning(GFARM_MSG_UNFIXED,
		    "get_gid(%s): %s", group, gfarm_error_string(e));
		return (gfarm_id_nogroup_gid());
	}
	return (gid);
}

static void
copy_gfs_stat(const char *path, SMB_STRUCT_STAT *dst, struct gfs_stat *src)
{
	memset(dst, 0, sizeof(*dst));
	dst->st_ex_dev = GFS_DEV;
	dst->st_ex_ino = src->st_ino;
	dst->st_ex_mode = src->st_mode;
	dst->st_ex_nlink = src->st_nlink;
	dst->st_ex_uid = get_uid(path, src->st_user);
	dst->st_ex_gid = get_gid(path, src->st_group);
	dst->st_ex_size = src->st_size;
	dst->st_ex_blksize = GFS_BLKSIZE;
	dst->st_ex_blocks = (src->st_size + STAT_BLKSIZ - 1) / STAT_BLKSIZ;
	dst->st_ex_atime.tv_sec = src->st_atimespec.tv_sec;
	dst->st_ex_atime.tv_nsec = src->st_atimespec.tv_nsec;
	dst->st_ex_mtime.tv_sec = src->st_mtimespec.tv_sec;
	dst->st_ex_mtime.tv_nsec = src->st_mtimespec.tv_nsec;
	dst->st_ex_ctime.tv_sec = src->st_ctimespec.tv_sec;
	dst->st_ex_ctime.tv_nsec = src->st_ctimespec.tv_nsec;
	/* XXX dst->st_ex_btime, dst->st_ex_calculated_birthtime */
}

static int
switch_user(const char *user)
{
	struct passwd *pwd = getpwnam(user);

	if (pwd != NULL)
		return (seteuid(pwd->pw_uid));
	errno = ENOENT;
	return (-1);
}

struct gfvfs_data {
	char tmp_path[PATH_MAX + 1];
	char *cwd;
};

static struct gfvfs_data *
gfvfs_data_init()
{
	struct gfvfs_data *gdata;

	GFARM_MALLOC(gdata);
	if (gdata == NULL)
		return (NULL);
	gdata->cwd = NULL;
	return (gdata);
}

static void
gfvfs_data_free(void **data)
{
	struct gfvfs_data *gdata = (struct gfvfs_data *)*data;

	free(gdata->cwd);
	free(gdata);
}

static const char *
gfvfs_fullpath(vfs_handle_struct *handle, const char *path)
{
	struct gfvfs_data *gdata = (struct gfvfs_data *)handle->data;
	const char *cwd = gdata->cwd;
	char *buf = gdata->tmp_path;

	if (cwd == NULL || path[0] == '/')
		return (path);
	if (path[0] == '\0') /* "" */
		return ((const char *)cwd);
	if (path[0] == '.') {
		if (path[1] == '\0') /* "." */
			return ((const char *)cwd);
		else if (path[1] == '/') /* "./NAME..." */
			path += 2;
	}

	if (cwd[0] == '/') {
		if (cwd[1] == '\0') /* rootdir */
			snprintf(buf, PATH_MAX + 1, "/%s", path);
		else
			snprintf(buf, PATH_MAX + 1, "%s/%s", cwd, path);
	} else
		snprintf(buf, PATH_MAX + 1, "/%s/%s", cwd, path);
	return ((const char *)buf);
}

/*
 * OPTIONS
 * gfarm:config = PATH
 */
static int
gfvfs_connect(vfs_handle_struct *handle, const char *service,
	const char *user)
{
	gfarm_error_t e;
	struct gfvfs_data *gdata;
	gfarm_off_t used, avail, files;
	uid_t uid = getuid(), saved_euid = geteuid();
	const char *config = lp_parm_const_string(SNUM(handle->conn),
	    "gfarm", "config", NULL);
	static const char log_id[] = "gfarm_samba";

	gflog_set_identifier(log_id);
	if (config != NULL)
		setenv("GFARM_CONFIG_FILE", config, 0);
	if (uid == 0) {
		if (switch_user(user) == -1) {
			int save_errno = errno;

			gflog_error(GFARM_MSG_UNFIXED,
			    "connect: unknown user=%s: %s",
			    user, strerror(errno));
			errno = save_errno;
			return (-1);
		}
	}

	e = gfarm_initialize(NULL, NULL);
	gflog_debug(GFARM_MSG_UNFIXED,
	    "connect: %p, service=%s, user=%s, uid=%d/%d, config=%s",
	    handle, service, user, getuid(), geteuid(), config);
	if (e != GFARM_ERR_NO_ERROR) {
		if (uid == 0) /* must exit as saved_euid */
			seteuid(saved_euid);
		gflog_error(GFARM_MSG_UNFIXED, "gfarm_initialize: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	/*
	 * Trying gfmd connection is nessessary here.  Because some
	 * VFS callbacks by euid==0 will be called after this
	 * SMB_VFS_CONNECT callback.  If a Gfarm connection by euid==0
	 * with GSI authentication succeeds once, the global user is
	 * recognized to be a user corresponding to the host
	 * certificate all the time.
	 *
	 * The callbacks behavior by euid==0 is:
	 * (samba_3.6.x)/source3/smbd/service.c#make_connection_snum()
	 */
	e = gfs_statfs(&used, &avail, &files);
	if (uid == 0) /* must exit as saved_euid */
		seteuid(saved_euid);
	if (e != GFARM_ERR_NO_ERROR) {
		(void)gfarm_terminate();
		gflog_error(GFARM_MSG_UNFIXED, "initial gfs_statfs: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	gfvfs_acl_id_init();

	gdata = gfvfs_data_init();
	if (gdata == NULL) {
		(void)gfarm_terminate();
		gflog_error(GFARM_MSG_UNFIXED, "connect: no memory");
		errno = ENOMEM;
		return (-1);
	}
	handle->data = gdata;
	handle->free_data = gfvfs_data_free;
	return (0);
}

static void
gfvfs_disconnect(vfs_handle_struct *handle)
{
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "disconnect: %p", handle);
	e = gfarm_terminate();
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfarm_terminate: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
	}
}

static uint64_t
gfvfs_disk_free(vfs_handle_struct *handle, const char *path,
	bool small_query, uint64_t *bsize, uint64_t *dfree, uint64_t *dsize)
{
	gfarm_off_t used, avail, files;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "disk_free: path=%s", path);
	e = gfs_statfs(&used, &avail, &files);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_statfs: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	*bsize = 1024;
	*dfree = avail;
	*dsize = used + avail;
	return (0);
}

static int
gfvfs_get_quota(vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype,
	unid_t id, SMB_DISK_QUOTA *dq)
{
	gflog_debug(GFARM_MSG_UNFIXED, "get_quota(ENOSYS): qtype=%d", qtype);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_set_quota(vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype,
	unid_t id, SMB_DISK_QUOTA *dq)
{
	gflog_debug(GFARM_MSG_UNFIXED, "set_quota(ENOSYS): qtype=%d", qtype);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_get_shadow_copy_data(vfs_handle_struct *handle, files_struct *fsp,
	struct shadow_copy_data *shadow_copy_data, bool labels)
{
	gflog_debug(GFARM_MSG_UNFIXED, "get_shadow_copy_data(ENOSYS): fsp=%p",
	    fsp);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_statvfs(struct vfs_handle_struct *handle, const char *path,
	struct vfs_statvfs_struct *statbuf)
{
	gfarm_off_t used, avail, files;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "statvfs: path=%s", path);
	e = gfs_statfs(&used, &avail, &files);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_statfs: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	statbuf->BlockSize = 1024;
	statbuf->TotalBlocks = used + avail;
	statbuf->BlocksAvail = avail;
	statbuf->UserBlocksAvail = avail;
	statbuf->TotalFileNodes = files;
	statbuf->FreeFileNodes = -1;
	return (0);
}

static uint32_t
gfvfs_fs_capabilities(struct vfs_handle_struct *handle,
	enum timestamp_set_resolution *p_ts_res)
{
	gflog_debug(GFARM_MSG_UNFIXED, "fs_capabilities: uid=%d/%d",
	    getuid(), geteuid());
	return (0);
}

struct gfvfs_dir {
	GFS_Dir dp;
	char *path;
};

static SMB_STRUCT_DIR *
gfvfs_opendir(vfs_handle_struct *handle, const char *fname,
	const char *mask, uint32 attr)
{
	GFS_Dir dp;
	struct gfvfs_dir *gdp;
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "opendir: path=%s, mask=%s",
	    fname, mask);
	fullpath = gfvfs_fullpath(handle, fname);
	e = gfs_opendir_caching(fullpath, &dp);
	if (e == GFARM_ERR_NO_ERROR) {
		GFARM_MALLOC(gdp);
		if (gdp != NULL)
			gdp->path = strdup(fullpath);
		if (gdp == NULL || gdp->path == NULL) {
			gflog_error(GFARM_MSG_UNFIXED, "opendir: no memory");
			free(gdp->path);
			free(gdp);
			gfs_closedir(dp);
			return (NULL);
		}
		gdp->dp = dp;
		return ((SMB_STRUCT_DIR *)gdp);
	}
	gflog_error(GFARM_MSG_UNFIXED, "gfs_opendir: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (NULL);
}

static SMB_STRUCT_DIR *
gfvfs_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
	const char *mask, uint32 attr)
{
	gflog_debug(GFARM_MSG_UNFIXED, "fdopendir: ENOSYS");
	errno = ENOSYS; /* use gfvfs_opendir() instead of this */
	return (NULL);
}

/* returns static region */
static SMB_STRUCT_DIRENT *
gfvfs_readdir(vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp,
	SMB_STRUCT_STAT *sbuf)
{
	struct gfvfs_dir *gdp = (struct gfvfs_dir *)dirp;
	struct gfs_dirent *de;
	static SMB_STRUCT_DIRENT ssd;
	struct gfs_stat st;
	char *path;
	size_t len;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "readdir: dir=%p", dirp);
	if (sbuf)
		SET_STAT_INVALID(*sbuf);

	e = gfs_readdir(gdp->dp, &de);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_readdir: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (NULL);
	}
	if (de == NULL)
		return (NULL);

	gflog_debug(GFARM_MSG_UNFIXED, "readdir: name=%s", de->d_name);
	ssd.d_ino = de->d_fileno;
	ssd.d_reclen = de->d_reclen;
	ssd.d_type = de->d_type;
	ssd.d_off = 0;
	strncpy(ssd.d_name, de->d_name, sizeof(ssd.d_name));
	if (sbuf) {
		/* gdp->path is fullpath */
		len = strlen(gdp->path) + strlen(de->d_name) + 2;
		GFARM_MALLOC_ARRAY(path, len);
		if (path == NULL)
			return (&ssd);
		snprintf(path, len, "%s/%s", gdp->path, de->d_name);
		gflog_debug(GFARM_MSG_UNFIXED, "lstat: path=%s", path);
		e = gfs_lstat_cached(path, &st);
		if (e == GFARM_ERR_NO_ERROR) {
			copy_gfs_stat(path, sbuf, &st);
			gfs_stat_free(&st);
		}
		free(path);
	}
	return (&ssd);
}

static void
gfvfs_seekdir(vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp, long offset)
{
	struct gfvfs_dir *gdp = (struct gfvfs_dir *)dirp;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "seekdir: dir=%p, offset=%ld",
	    dirp, offset);
	e = gfs_seekdir(gdp->dp, offset);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_seekdir: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
	}
	return;
}

static long
gfvfs_telldir(vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp)
{
	gfarm_off_t off;
	struct gfvfs_dir *gdp = (struct gfvfs_dir *)dirp;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "telldir: dir=%p", dirp);
	e = gfs_telldir(gdp->dp, &off);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_telldir: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	return ((long)off);
}

static void
gfvfs_rewind_dir(vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp)
{
	struct gfvfs_dir *gdp = (struct gfvfs_dir *)dirp;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "rewind_dir: dir=%p", dirp);
	e = gfs_seekdir(gdp->dp, 0);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_seekdir: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
	}
	return;
}

static void
uncache_parent(const char *path)
{
	char *p = gfarm_url_dir(path);

	if (p == NULL) {
		gflog_error(GFARM_MSG_UNFIXED, "uncache_parent(%s): no memory",
		    path);
		return;
	}
	gflog_debug(GFARM_MSG_UNFIXED, "uncache_parent: parent=%s, path=%s",
	    p, path);
	gfs_stat_cache_purge(p);
	free(p);
}

static int
gfvfs_mkdir(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "mkdir: path=%s, mode=%o", path, mode);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_mkdir(fullpath, mode & GFARM_S_ALLPERM);
	if (e == GFARM_ERR_NO_ERROR) {
		uncache_parent(fullpath);
		return (0);
	}
	gfvfs_error(GFARM_MSG_UNFIXED, "gfs_mkdir", e);
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_rmdir(vfs_handle_struct *handle, const char *path)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "rmdir: path=%s", path);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_rmdir(fullpath);
	if (e == GFARM_ERR_NO_ERROR) {
		gfs_stat_cache_purge(fullpath);
		uncache_parent(fullpath);
		return (0);
	}
	gflog_error(GFARM_MSG_UNFIXED, "gfs_rmdir: %s", gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_closedir(vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp)
{
	struct gfvfs_dir *gdp = (struct gfvfs_dir *)dirp;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "closedir: dir=%p", dirp);
	e = gfs_closedir(gdp->dp);
	free(gdp->path);
	free(gdp);
	if (e == GFARM_ERR_NO_ERROR)
		return (0);
	gflog_error(GFARM_MSG_UNFIXED, "gfs_closedir: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static void
gfvfs_init_search_op(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp)
{
	gflog_debug(GFARM_MSG_UNFIXED, "init_search_op: dir=%p", dirp);
	return;
}

static int
gfvfs_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
	files_struct *fsp, int flags, mode_t mode)
{
	int g_flags = open_flags_gfarmize(flags);
	const char *fname = smb_fname->base_name, *fullpath;
	const char *stream = smb_fname->stream_name;
	char *msg;
	GFS_File gf;
	GFS_Dir dp;
	struct gfvfs_dir *gdp;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED,
	    "open: fsp=%p, path=%s%s, flags=%x, mode=%o, is_dir=%d",
	    fsp, fname, stream != NULL ? stream : "",
	    flags, mode, fsp->is_directory);
	if (stream != NULL) {
		errno = ENOENT;
		return (-1);
	}
	if (g_flags < 0) {
		gflog_error(GFARM_MSG_UNFIXED, "open: %s", strerror(EINVAL));
		errno = EINVAL;
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, fname);
	if (fsp->is_directory &&
	    (g_flags & GFARM_FILE_ACCMODE) == GFARM_FILE_RDONLY) {
		msg = "gfs_opendir";
		e = gfs_opendir(fullpath, &dp);
	} else if (flags & O_CREAT) {
		msg = "gfs_pio_create";
		e = gfs_pio_create(fullpath, g_flags,
		    mode & GFARM_S_ALLPERM, &gf);
	} else {
		msg = "gfs_pio_open";
		e = gfs_pio_open(fullpath, g_flags, &gf);
	}
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, msg, e);
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	if (flags & O_CREAT)
		uncache_parent(fullpath);
	else
		gfs_stat_cache_purge(fullpath);
	/*
	 * XXX - gen_id is assigned in files.c as a unique number
	 * identifying this fsp over the life of this pid.  I guess it
	 * is safe to use to store GFS_File.
	 */
	if (fsp->is_directory) {
		GFARM_MALLOC(gdp);
		if (gdp != NULL)
			gdp->path = strdup(fullpath);
		if (gdp == NULL || gdp->path == NULL) {
			gflog_error(GFARM_MSG_UNFIXED, "open: no memory");
			free(gdp->path);
			free(gdp);
			gfs_closedir(dp);
			errno = ENOMEM;
			return (-1);
		}
		gdp->dp = dp;
		fsp->fh->gen_id = (unsigned long)gdp;
		return (0); /* dummy */
	} else {
		fsp->fh->gen_id = (unsigned long)gf;
		return (gfs_pio_fileno(gf)); /* although do not use this */
	}
}

static NTSTATUS
gfvfs_create_file(struct vfs_handle_struct *handle, struct smb_request *req,
	uint16_t root_dir_fid, struct smb_filename *smb_fname,
	uint32_t access_mask, uint32_t share_access,
	uint32_t create_disposition, uint32_t create_options,
	uint32_t file_attributes, uint32_t oplock_request,
	uint64_t allocation_size, uint32_t private_flags,
	struct security_descriptor *sd, struct ea_list *ea_list,
	files_struct **result_fsp, int *pinfo)
{
	NTSTATUS result;
	const char *str_create_disposition;

	gflog_debug(GFARM_MSG_UNFIXED, "create_file(VFS_NEXT): %s%s",
	    smb_fname->base_name,
	    smb_fname->stream_name != NULL ? smb_fname->stream_name : "");

	*result_fsp = NULL;
	result = SMB_VFS_NEXT_CREATE_FILE(
	    handle, req, root_dir_fid, smb_fname, access_mask, share_access,
	    create_disposition, create_options, file_attributes,
	    oplock_request, allocation_size, private_flags, sd, ea_list,
	    result_fsp, pinfo);

	switch (create_disposition) {
	case FILE_SUPERSEDE:
		str_create_disposition = "SUPERSEDE";
		break;
	case FILE_OVERWRITE_IF:
		str_create_disposition = "OVERWRITE_IF";
		break;
	case FILE_OPEN:
		str_create_disposition = "OPEN";
		break;
	case FILE_OVERWRITE:
		str_create_disposition = "OVERWRITE";
		break;
	case FILE_CREATE:
		str_create_disposition = "CREATE";
		break;
	case FILE_OPEN_IF:
		str_create_disposition = "OPEN_IF";
		break;
	default:
		str_create_disposition = "UNKNOWN";
	}
	gflog_debug(GFARM_MSG_UNFIXED,
	    "create_file: %p|%s|0x%x|%s|%s|%s%s",
	    *result_fsp, nt_errstr(result), access_mask,
	    create_options & FILE_DIRECTORY_FILE ? "DIR" : "FILE",
	    str_create_disposition, smb_fname->base_name,
	    smb_fname->stream_name != NULL ? smb_fname->stream_name : "");

	return (result);
}

static int
gfvfs_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	gfarm_error_t e;
	char *msg;

	gflog_debug(GFARM_MSG_UNFIXED, "close_fn: fsp=%p", fsp);
	if (!fsp->is_directory) {
		msg = "gfs_pio_close";
		e = gfs_pio_close((GFS_File)fsp->fh->gen_id);
	} else {
		struct gfvfs_dir *gdp = (struct gfvfs_dir *)fsp->fh->gen_id;

		msg = "gfs_closedir";
		e = gfs_closedir(gdp->dp);
		free(gdp->path);
		free(gdp);
	}
	if (e == GFARM_ERR_NO_ERROR)
		return (0);
	gflog_error(GFARM_MSG_UNFIXED, "%s: %s", msg, gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static ssize_t
gfvfs_vfs_read(vfs_handle_struct *handle, files_struct *fsp,
	void *data, size_t n)
{
	gfarm_error_t e;
	int rv;

	gflog_debug(GFARM_MSG_UNFIXED, "read: fsp=%p, size=%lu", fsp,
	    (unsigned long)n);
	e = gfs_pio_read((GFS_File)fsp->fh->gen_id, data, n, &rv);
	if (e == GFARM_ERR_NO_ERROR)
		return (rv);
	gflog_error(GFARM_MSG_UNFIXED, "gfs_pio_read: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static ssize_t
gfvfs_pread(vfs_handle_struct *handle, files_struct *fsp,
	void *data, size_t n, SMB_OFF_T offset)
{
	gfarm_error_t e;
	gfarm_off_t off;
	GFS_File gf = (GFS_File)fsp->fh->gen_id;
	int rv;

	gflog_debug(GFARM_MSG_UNFIXED, "pread: fsp=%p, size=%lu, offset=%lld",
	    fsp, (unsigned long)n, (long long)offset);
	e = gfs_pio_seek(gf, (off_t)offset, GFARM_SEEK_SET, &off);
	if (e == GFARM_ERR_NO_ERROR)
		e = gfs_pio_read(gf, data, n, &rv);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_pio_pread: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	return (rv);
}

static ssize_t
gfvfs_write(vfs_handle_struct *handle, files_struct *fsp,
	const void *data, size_t n)
{
	gfarm_error_t e;
	int rv;

	gflog_debug(GFARM_MSG_UNFIXED, "write: fsp=%p, size=%lu", fsp,
	    (unsigned long)n);
	e = gfs_pio_write((GFS_File)fsp->fh->gen_id, data, n, &rv);
	if (e == GFARM_ERR_NO_ERROR) {
		const char *fullpath =
		    gfvfs_fullpath(handle, fsp->fsp_name->base_name);

		gfs_stat_cache_purge(fullpath);
		return (rv);
	}
	gflog_error(GFARM_MSG_UNFIXED, "gfs_pio_write: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static ssize_t
gfvfs_pwrite(vfs_handle_struct *handle, files_struct *fsp,
	const void *data, size_t n, SMB_OFF_T offset)
{
	gfarm_error_t e;
	gfarm_off_t off;
	int rv;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "pwrite: fsp=%p, size=%lu, offset=%lld",
	    data, (unsigned long)n, (long long)offset);
	e = gfs_pio_seek((GFS_File)fsp->fh->gen_id, offset, GFARM_SEEK_SET,
		&off);
	if (e == GFARM_ERR_NO_ERROR)
		e = gfs_pio_write((GFS_File)fsp->fh->gen_id, data, n, &rv);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_pio_pwrite: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, fsp->fsp_name->base_name);
	gfs_stat_cache_purge(fullpath);
	return (rv);
}

static SMB_OFF_T
gfvfs_lseek(vfs_handle_struct *handle, files_struct *fsp,
	SMB_OFF_T offset, int whence)
{
	gfarm_off_t off;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "lseek: fsp=%p, offset=%ld, whence=%d",
	    fsp, (long)offset, whence);
	e = gfs_pio_seek((GFS_File)fsp->fh->gen_id, offset, GFARM_SEEK_SET,
		&off);
	if (e == GFARM_ERR_NO_ERROR)
		return (off);
	gflog_error(GFARM_MSG_UNFIXED, "gfs_pio_seek: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static ssize_t
gfvfs_sendfile(vfs_handle_struct *handle, int tofd, files_struct *fromfsp,
	const DATA_BLOB *hdr, SMB_OFF_T offset, size_t n)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "sendfile(ENOSYS): to_fd=%d, from_fsp=%p", tofd, fromfsp);
	errno = ENOSYS;
	return (-1);
}

static ssize_t
gfvfs_recvfile(vfs_handle_struct *handle, int fromfd, files_struct *tofsp,
	SMB_OFF_T offset, size_t n)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "recvfile(ENOSYS): from_fd=%d, to_fsp=%p", fromfd, tofsp);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_rename(vfs_handle_struct *handle,
	const struct smb_filename *smb_fname_src,
	const struct smb_filename *smb_fname_dst)
{
	const char *oldname = smb_fname_src->base_name;
	const char *old_stream = smb_fname_src->stream_name;
	const char *newname = smb_fname_dst->base_name;
	const char *new_stream = smb_fname_dst->stream_name;
	char *fullold, *fullnew;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "rename: old=%s%s, new=%s%s",
	    oldname, old_stream != NULL ? old_stream : "",
	    newname, new_stream != NULL ? new_stream : "");
	if (old_stream != NULL || new_stream != NULL) {
		errno = ENOENT;
		return (-1);
	}
	fullold = strdup(gfvfs_fullpath(handle, oldname));
	fullnew = strdup(gfvfs_fullpath(handle, newname));
	if (fullold == NULL || fullnew == NULL) {
		free(fullold);
		free(fullnew);
		gflog_error(GFARM_MSG_UNFIXED, "rename: no memory");
		errno = ENOMEM;
		return (-1);
	}
	e = gfs_rename(fullold, fullnew);
	if (e == GFARM_ERR_NO_ERROR) {
		gfs_stat_cache_purge(fullold);
		uncache_parent(fullold);
		gfs_stat_cache_purge(fullnew);
		uncache_parent(fullnew);
		free(fullold);
		free(fullnew);
		return (0);
	}
	free(fullold);
	free(fullnew);
	gflog_error(GFARM_MSG_UNFIXED,
	    "gfs_rename: %s", gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_fsync(vfs_handle_struct *handle, files_struct *fsp)
{
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "fsync: fsp=%p", fsp);
	e = gfs_pio_sync((GFS_File)fsp->fh->gen_id);
	if (e == GFARM_ERR_NO_ERROR)
		return (0);
	gflog_error(GFARM_MSG_UNFIXED, "gfs_pio_sync: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	struct gfs_stat st;
	const char *path = smb_fname->base_name, *fullpath;
	const char *stream = smb_fname->stream_name;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "stat: path=%s%s",
	    path, stream != NULL ? stream : "");
	if (stream != NULL) {
		errno = ENOENT;
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_stat_cached(fullpath, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_stat", e);
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	copy_gfs_stat(fullpath, &smb_fname->st, &st);
	gfs_stat_free(&st);
	return (0);
}

static int
gfvfs_fstat(vfs_handle_struct *handle, files_struct *fsp,
	SMB_STRUCT_STAT *sbuf)
{
	struct gfs_stat st;
	char *msg;
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "fstat: fsp=%p, is_dir=%d",
	    fsp, fsp->is_directory);
	if (!fsp->is_directory) {
		msg = "gfs_pio_stat";
		e = gfs_pio_stat((GFS_File)fsp->fh->gen_id, &st);
	} else {
		msg = "gfs_statdir";
		e = gfs_statdir(
		    ((struct gfvfs_dir *)fsp->fh->gen_id)->dp, &st);
	}
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, msg, e);
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, fsp->fsp_name->base_name);
	copy_gfs_stat(fullpath, sbuf, &st);
	gfs_stat_free(&st);
	return (0);
}

static int
gfvfs_lstat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	struct gfs_stat st;
	const char *path = smb_fname->base_name, *fullpath;
	const char *stream = smb_fname->stream_name;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "lstat: path=%s%s",
	    path, stream != NULL ? stream : "");
	if (stream != NULL) {
		errno = ENOENT;
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_lstat_cached(fullpath, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_lstat", e);
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	copy_gfs_stat(fullpath, &smb_fname->st, &st);
	gfs_stat_free(&st);
	return (0);
}

/* should not be ENOSYS */
static uint64_t
gfvfs_get_alloc_size(struct vfs_handle_struct *handle,
	struct files_struct *fsp, const SMB_STRUCT_STAT *sbuf)
{
	uint64_t result;

	gflog_debug(GFARM_MSG_UNFIXED, "get_alloc_size: fsp=%p, st_size %lld",
	    fsp, (long long)sbuf->st_ex_size);
	if (S_ISDIR(sbuf->st_ex_mode))
		return (0);
	result = get_file_size_stat(sbuf);
	if (fsp && fsp->initial_allocation_size)
		result = MAX(result, fsp->initial_allocation_size);
	result = smb_roundup(handle->conn, result);
	gflog_debug(GFARM_MSG_UNFIXED, "get_alloc_size: result %lld",
	    (long long)result);
	return (result);
}

static int
gfvfs_unlink(vfs_handle_struct *handle, const struct smb_filename *smb_fname)
{
	const char *path = smb_fname->base_name;
	const char *stream = smb_fname->stream_name;
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "unlink: path=%s%s",
	    path, stream != NULL ? stream : "");
	if (stream != NULL) {
		errno = ENOENT;
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_unlink(fullpath);
	if (e == GFARM_ERR_NO_ERROR) {
		gfs_stat_cache_purge(fullpath);
		uncache_parent(fullpath);
		return (0);
	}
	gflog_error(GFARM_MSG_UNFIXED, "gfs_unlink: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_chmod(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "chmod: path=%s, mode=%o", path, mode);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_chmod(fullpath, mode & GFARM_S_ALLPERM);
	if (e == GFARM_ERR_NO_ERROR) {
		gfs_stat_cache_purge(fullpath);
		return (0);
	}
	gflog_error(GFARM_MSG_UNFIXED, "gfs_chmod: %s", gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	gflog_debug(GFARM_MSG_UNFIXED, "fchmod(ENOSYS): fsp=%p, mode=%o",
	    fsp, mode);
	errno = ENOSYS; /* XXX gfs_fchmod() */
	return (-1);
}

static int
gfvfs_chown(vfs_handle_struct *handle, const char *path,
	uid_t uid, gid_t gid)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "chown(ENOSYS): path=%s, uid=%d, gid=%d", path, uid, gid);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_fchown(vfs_handle_struct *handle, files_struct *fsp,
	uid_t uid, gid_t gid)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "fchown(ENOSYS): fsp=%p, uid=%d, gid=%d", fsp, uid, gid);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_lchown(vfs_handle_struct *handle, const char *path,
	uid_t uid, gid_t gid)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "lchown(ENOSYS): path=%s, uid=%d, gid=%d", path, uid, gid);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_chdir(vfs_handle_struct *handle, const char *path)
{
	char *fullpath;
	struct gfvfs_data *gdata = (struct gfvfs_data *)handle->data;

	gflog_debug(GFARM_MSG_UNFIXED, "chdir: path=%s, uid=%d/%d",
	    path, getuid(), geteuid());
	fullpath = strdup(gfvfs_fullpath(handle, path));
	if (fullpath == NULL) {
		gflog_error(GFARM_MSG_UNFIXED, "chdir: no memory");
		errno = ENOMEM;;
		return (-1);
	}
	if (gdata->cwd != NULL)
		free(gdata->cwd);
	gdata->cwd = fullpath;
	return (0);
}

static char *
gfvfs_getwd(vfs_handle_struct *handle, char *buf)
{
	struct gfvfs_data *gdata = (struct gfvfs_data *)handle->data;

	gflog_debug(GFARM_MSG_UNFIXED, "getwd: cwd=%s", gdata->cwd);
	return (gdata->cwd);
}

/* should not be ENOSYS */
static int
gfvfs_ntimes(vfs_handle_struct *handle, const struct smb_filename *smb_fname,
	struct smb_file_time *ft)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "ntimes: path=%s%s",
	    smb_fname->base_name,
	    smb_fname->stream_name != NULL ? smb_fname->stream_name : "");
	if (smb_fname->stream_name != NULL) {
		errno = ENOENT;
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, smb_fname->base_name);

	if (ft != NULL) {
		struct gfarm_timespec gt[2];

		if (null_timespec(ft->atime))
			ft->atime = smb_fname->st.st_ex_atime;
		if (null_timespec(ft->mtime))
			ft->mtime = smb_fname->st.st_ex_mtime;

		/* XXX ft->create_time */

		if ((timespec_compare(&ft->atime,
		     &smb_fname->st.st_ex_atime) == 0) &&
		    (timespec_compare(&ft->mtime,
		     &smb_fname->st.st_ex_mtime) == 0))
			return (0);

		gt[0].tv_sec = ft->atime.tv_sec;
		gt[0].tv_nsec = ft->atime.tv_nsec;
		gt[1].tv_sec = ft->mtime.tv_sec;
		gt[1].tv_nsec = ft->mtime.tv_nsec;
		e = gfs_lutimes(fullpath, gt);
	} else
		e = gfs_lutimes(fullpath, NULL);

	if (e == GFARM_ERR_NO_ERROR) {
		gfs_stat_cache_purge(fullpath);
		uncache_parent(fullpath);
		return (0);
	}
	gflog_debug(GFARM_MSG_UNFIXED, "gfs_lutimes: %s: %s",
	    fullpath, gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_ftruncate(vfs_handle_struct *handle, files_struct *fsp, SMB_OFF_T offset)
{
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "ftruncate: fsp=%p, offset=%lld",
	    fsp, (long long)offset);
	e = gfs_pio_truncate((GFS_File)fsp->fh->gen_id, offset);
	if (e == GFARM_ERR_NO_ERROR) {
		const char *fullpath =
		    gfvfs_fullpath(handle, fsp->fsp_name->base_name);

		gfs_stat_cache_purge(fullpath);
		return (0);
	}
	gflog_error(GFARM_MSG_UNFIXED, "gfs_pio_truncate: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_fallocate(vfs_handle_struct *handle, files_struct *fsp,
	enum vfs_fallocate_mode mode, SMB_OFF_T offset, SMB_OFF_T len)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "fallocate(ENOSYS): fsp=%p, off=%lld, len=%lld",
	    fsp, (long long)offset, (long long)len);
	errno = ENOSYS;
	return (-1);
}

static bool
gfvfs_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
	SMB_OFF_T offset, SMB_OFF_T count, int type)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "lock(ENOSYS): fsp=%p, op=%o, offset=%lld, count=%lld, type=%o",
	    fsp, op, (long long)offset, (long long)count, type);
	errno = ENOSYS;
	return (false);
}

static int
gfvfs_kernel_flock(struct vfs_handle_struct *handle, struct files_struct *fsp,
	uint32 share_mode, uint32 access_mask)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "kernel_flock(ignored): fsp=%p, share_mode=%o, access_mask=%o",
	    fsp, share_mode, access_mask);
#if 0 /* should not be ENOSYS */
	gflog_info(GFARM_MSG_UNFIXED, "kernel_flock: %s", strerror(ENOSYS));
	errno = ENOSYS;
	return (-1);
#else
	return (0); /* ignore ENOSYS */
#endif
}

static int
gfvfs_linux_setlease(struct vfs_handle_struct *handle,
	struct files_struct *fsp, int leasetype)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "linux_setlease(ENOSYS): fsp=%p, type=%o", fsp, leasetype);
	errno = ENOSYS;
	return (-1);
}

static bool
gfvfs_getlock(vfs_handle_struct *handle, files_struct *fsp,
	SMB_OFF_T *poffset, SMB_OFF_T *pcount, int *ptype, pid_t *ppid)
{
	gflog_debug(GFARM_MSG_UNFIXED, "getlock(ENOSYS): fsp=%p", fsp);
#if 1
	errno = ENOSYS;
	return (false);
#else
	*ptype = F_UNLCK;
	return (0);
#endif
}

static int
gfvfs_symlink(vfs_handle_struct *handle, const char *oldpath,
	const char *newpath)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "symlink: old=%s, new=%s",
	    oldpath, newpath);
	fullpath = gfvfs_fullpath(handle, newpath);
	e = gfs_symlink(oldpath, fullpath);
	if (e == GFARM_ERR_NO_ERROR) {
		uncache_parent(fullpath);
		return (0);
	}
	gflog_error(GFARM_MSG_UNFIXED, "gfs_symlink: %s",
	    gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_vfs_readlink(vfs_handle_struct *handle, const char *path,
	char *buf, size_t bufsiz)
{
	char *old;
	size_t len;
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "readlink: path=%s", path);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_readlink(fullpath, &old);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_readlink: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	len = strlen(old);
	if (len >= bufsiz)
		len = bufsiz - 1;
	memcpy(buf, old, len);
	buf[len] = '\0';
	free(old);
	return (len);
}

static int
gfvfs_link(vfs_handle_struct *handle, const char *oldpath, const char *newpath)
{
	gfarm_error_t e;
	char *fullold, *fullnew;

	gflog_debug(GFARM_MSG_UNFIXED, "link: old=%s, new=%s",
	    oldpath, newpath);
	fullold = strdup(gfvfs_fullpath(handle, oldpath));
	fullnew = strdup(gfvfs_fullpath(handle, newpath));
	if (fullold == NULL || fullnew == NULL) {
		free(fullold);
		free(fullnew);
		gflog_error(GFARM_MSG_UNFIXED, "link: no memory");
		errno = ENOMEM;
		return (-1);
	}
	e = gfs_link(fullold, fullnew);
	if (e == GFARM_ERR_NO_ERROR) {
		uncache_parent(fullnew);
		free(fullold);
		free(fullnew);
		return (0);
	}
	free(fullold);
	free(fullnew);
	gflog_error(GFARM_MSG_UNFIXED, "gfs_link: %s", gfarm_error_string(e));
	errno = gfarm_error_to_errno(e);
	return (-1);
}

static int
gfvfs_mknod(vfs_handle_struct *handle, const char *path, mode_t mode,
	SMB_DEV_T dev)
{
	GFS_File gf;
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "mknod: path=%s, mode=%o", path, mode);
	if (!S_ISREG(mode)) {
		gflog_error(GFARM_MSG_UNFIXED, "mknod: %s", strerror(ENOSYS));
		errno = ENOSYS;
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_pio_create(fullpath, GFARM_FILE_WRONLY,
	    mode & GFARM_S_ALLPERM, &gf);
	if (e == GFARM_ERR_NO_ERROR)
		e = gfs_pio_close(gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_pio_mknod: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	uncache_parent(fullpath);
	return (0);
}

#define GFARM_PREFIX	"gfarm:"
#define SLASH_SLASH	"//"

static char *
skip_prefix(char *url)
{
	if (url == NULL)
		return (NULL);
	if (strncmp(url, GFARM_PREFIX, strlen(GFARM_PREFIX)) == 0)
		url += strlen(GFARM_PREFIX);
	if (strncmp(url, SLASH_SLASH, strlen(SLASH_SLASH)) == 0)
		url += strlen(SLASH_SLASH);
	/* skip hostname */
	if (isalpha(*url))
		while (isalnum(*url) || *url == '.' || *url == '-')
			++url;
	if (*url == ':')
		++url;
	/* skip port */
	while (isdigit(*url))
		++url;
	return (url);
}

static char *
gfvfs_realpath(vfs_handle_struct *handle, const char *path)
{
	const char *fullpath;
	char *rpath, *skip_path;
	gfarm_error_t e;

	gflog_debug(GFARM_MSG_UNFIXED, "realpath: path=%s, uid=%d/%d",
	    path, getuid(), geteuid());
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_realpath(fullpath, &rpath); /* slow? */
	if (e == GFARM_ERR_NO_ERROR) {
		skip_path = strdup(skip_prefix(rpath));
		free(rpath);
		if (skip_path != NULL) {
			gflog_debug(GFARM_MSG_UNFIXED, "realpath: result=%s",
			    skip_path);
		} else {
			gflog_error(GFARM_MSG_UNFIXED, "realpath: no memory");
			errno = ENOMEM;
		}
		return (skip_path);
	}
	gfvfs_error(GFARM_MSG_UNFIXED, "realpath", e);
	errno = gfarm_error_to_errno(e);
	return (NULL);
}

static NTSTATUS
gfvfs_notify_watch(struct vfs_handle_struct *handle,
	struct sys_notify_context *ctx, struct notify_entry *e,
	void (*callback)(struct sys_notify_context *ctx, void *private_data,
		struct notify_event *ev),
	void *private_data, void *handle_p)
{
	gflog_debug(GFARM_MSG_UNFIXED, "notify_watch(ENOSYS)");
	return (NT_STATUS_NOT_IMPLEMENTED);
}

static int
gfvfs_chflags(vfs_handle_struct *handle, const char *path, uint flags)
{
	gflog_debug(GFARM_MSG_UNFIXED, "chflags(ENOSYS): path=%s, flags=%d",
	    path, flags);
	errno = ENOSYS;
	return (-1);
}

static struct file_id
gfvfs_file_id_create(vfs_handle_struct *handle, const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id;

	gflog_debug(GFARM_MSG_UNFIXED,
	    "file_id_create: st_dev=%lld, st_ino=%lld",
	    (long long)sbuf->st_ex_dev, (long long)sbuf->st_ex_ino);
	ZERO_STRUCT(id);
	id.devid = sbuf->st_ex_dev; /* XXX not implemented */
	id.inode = sbuf->st_ex_ino;
	/* id.extid is unused by default */
	return (id);
}

static NTSTATUS
gfvfs_streaminfo(struct vfs_handle_struct *handle, struct files_struct *fsp,
	const char *fname, TALLOC_CTX *mem_ctx, unsigned int *num_streams,
	struct stream_struct **streams)
{
	gflog_debug(GFARM_MSG_UNFIXED, "streaminfo(VFS_NEXT): fsp=%p, path=%s",
	    fsp, fname);
	return (SMB_VFS_NEXT_STREAMINFO(handle, fsp, fname, mem_ctx,
	    num_streams, streams));
}

static int
gfvfs_get_real_filename(
	struct vfs_handle_struct *handle,
	const char *path,
	const char *name,
	TALLOC_CTX *mem_ctx,
	char **found_name)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "get_real_filename(EOPNOTSUPP): path=%s, name=%s", path, name);
	errno = EOPNOTSUPP; /* should not be ENOSYS */
	return (-1);
}

static const char *
gfvfs_connectpath(struct vfs_handle_struct *handle, const char *filename)
{
	const char *result = SMB_VFS_NEXT_CONNECTPATH(handle, filename);

	gflog_debug(GFARM_MSG_UNFIXED,
	    "connectpath(VFS_NEXT): path=%s, result=%s",
	    filename, result);
	return (result);
}

static NTSTATUS
gfvfs_brl_lock_windows(
	struct vfs_handle_struct *handle,
	struct byte_range_lock *br_lck,
	struct lock_struct *plock,
	bool blocking_lock,
	struct blocking_lock_record *blr)
{
	gflog_debug(GFARM_MSG_UNFIXED, "brl_lock_windows(VFS_NEXT): fsp=%p",
	    br_lck->fsp);
	return (SMB_VFS_NEXT_BRL_LOCK_WINDOWS(handle, br_lck, plock,
	    blocking_lock, blr));
}

static bool
gfvfs_brl_unlock_windows(
	struct vfs_handle_struct *handle,
	struct messaging_context *msg_ctx,
	struct byte_range_lock *br_lck,
	const struct lock_struct *plock)
{
	gflog_debug(GFARM_MSG_UNFIXED, "brl_unlock_windows(VFS_NEXT): fsp=%p",
	    br_lck->fsp);
	return (SMB_VFS_NEXT_BRL_UNLOCK_WINDOWS(handle, msg_ctx,
	    br_lck, plock));
}

static bool
gfvfs_brl_cancel_windows(
	struct vfs_handle_struct *handle,
	struct byte_range_lock *br_lck,
	struct lock_struct *plock,
	struct blocking_lock_record *blr)
{
	gflog_debug(GFARM_MSG_UNFIXED, "brl_cancel_windows(VFS_NEXT): fsp=%p",
	    br_lck->fsp);
	return (SMB_VFS_NEXT_BRL_CANCEL_WINDOWS(handle, br_lck, plock, blr));
}

static bool
gfvfs_strict_lock(
	struct vfs_handle_struct *handle,
	struct files_struct *fsp,
	struct lock_struct *plock)
{
	gflog_debug(GFARM_MSG_UNFIXED, "strict_lock(VFS_NEXT): fsp=%p", fsp);
	/* should not be ENOSYS */
	return (SMB_VFS_NEXT_STRICT_LOCK(handle, fsp, plock));
}

static void
gfvfs_strict_unlock(
	struct vfs_handle_struct *handle,
	struct files_struct *fsp,
	struct lock_struct *plock)
{
	gflog_debug(GFARM_MSG_UNFIXED, "strict_unlock(VFS_NEXT): fsp=%p", fsp);
	SMB_VFS_NEXT_STRICT_UNLOCK(handle, fsp, plock);
}

static NTSTATUS
gfvfs_translate_name(
	struct vfs_handle_struct *handle,
	const char *mapped_name,
	enum vfs_translate_direction direction,
	TALLOC_CTX *mem_ctx,
	char **pmapped_name)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "translate_name(none mapped): name=%s", mapped_name);
	/* should not be NT_STATUS_NOT_IMPLEMENTED */
	return (NT_STATUS_NONE_MAPPED);
}

static NTSTATUS
gfvfs_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
	uint32 security_info, struct security_descriptor **ppdesc)
{
	gflog_debug(GFARM_MSG_UNFIXED, "fget_nt_acl(VFS_NEXT): fsp=%p", fsp);
	return (SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, ppdesc));
}

static NTSTATUS
gfvfs_get_nt_acl(vfs_handle_struct *handle, const char *name,
	uint32 security_info, struct security_descriptor **ppdesc)
{
	gflog_debug(GFARM_MSG_UNFIXED, "get_nt_acl(VFS_NEXT): path=%s", name);
	return (SMB_VFS_NEXT_GET_NT_ACL(handle, name, security_info, ppdesc));
}

static NTSTATUS
gfvfs_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
	uint32 si_sent, const struct security_descriptor *psd)
{
	gflog_debug(GFARM_MSG_UNFIXED, "fset_nt_acl(VFS_NEXT): fsp=%p", fsp);
	return (SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, si_sent, psd));
}

static int
gfvfs_chmod_acl(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	gflog_debug(GFARM_MSG_UNFIXED, "chmod_acl: path=%s, mode=%o",
	    path, mode);
	return (gfvfs_chmod(handle, path, mode));
}

static int
gfvfs_fchmod_acl(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	gflog_debug(GFARM_MSG_UNFIXED, "fchmod_acl: fsp=%p, mode=%o",
	    fsp, mode);
	return (gfvfs_fchmod(handle, fsp, mode));
}

static int
smb_acl_type_to_gfarm_acl_type(const char *path, const char *diag,
	SMB_ACL_TYPE_T s_type, gfarm_acl_type_t *g_typep)
{
	switch (s_type) {
	case SMB_ACL_TYPE_ACCESS:
		*g_typep = GFARM_ACL_TYPE_ACCESS;
		gflog_debug(GFARM_MSG_UNFIXED,
		    "%s[access]: path=%s", diag, path);
		return (1);
	case SMB_ACL_TYPE_DEFAULT:
		*g_typep = GFARM_ACL_TYPE_DEFAULT;
		gflog_debug(GFARM_MSG_UNFIXED,
		    "%s[default]: path=%s", diag, path);
		return (1);
	default:
		gflog_debug(GFARM_MSG_UNFIXED,
		    "%s[EINVAL]: path=%s", diag, path);
		return (0);
	}
}

static SMB_ACL_T
gfvfs_sys_acl_get_file(vfs_handle_struct *handle, const char *path,
	SMB_ACL_TYPE_T s_type)
{
	SMB_ACL_T s_acl;
	gfarm_error_t e;
	gfarm_acl_t g_acl;
	gfarm_acl_type_t g_type;
	int save_errno;
	const char *fullpath;
	static const char diag[] = "sys_acl_get_file";

	fullpath = gfvfs_fullpath(handle, path);
	if (!smb_acl_type_to_gfarm_acl_type(fullpath, diag, s_type, &g_type)) {
		errno = EINVAL;
		return (NULL);
	}
	e = gfs_acl_get_file_cached(fullpath, g_type, &g_acl);
	if (e == GFARM_ERR_NO_SUCH_OBJECT && g_type == GFARM_ACL_TYPE_ACCESS) {
		struct gfs_stat st;

		e = gfs_lstat_cached(fullpath, &st);
		if (e != GFARM_ERR_NO_ERROR) {
			gflog_error(GFARM_MSG_UNFIXED, "gfs_lstat: %s: %s",
			    fullpath, gfarm_error_string(e));
			errno = gfarm_error_to_errno(e);
			return (NULL);
		}
		e = gfs_acl_from_mode(st.st_mode, &g_acl);
		gfs_stat_free(&st);
	}
	if (e != GFARM_ERR_NO_ERROR) {
		if (e == GFARM_ERR_NO_SUCH_OBJECT)
			gflog_debug(GFARM_MSG_UNFIXED,
			    "gfs_acl_get_file_cached[%s]: %s: %s",
			    g_type == GFARM_ACL_TYPE_ACCESS ?
			    "access" : "default",
			    fullpath, gfarm_error_string(e));
		else
			gflog_error(GFARM_MSG_UNFIXED,
			    "gfs_acl_get_file_cached[%s]: %s: %s",
			    g_type == GFARM_ACL_TYPE_ACCESS ?
			    "access" : "default",
			    fullpath, gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (NULL);
	}
	s_acl = gfvfs_gfarm_acl_to_smb_acl(fullpath, g_acl);
	save_errno = errno;
	gfs_acl_free(g_acl);
	errno = save_errno;
	return (s_acl);
}

static SMB_ACL_T
gfvfs_sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_get_fd(ENOSYS): fsp=%p", fsp);
	errno = ENOSYS; /* XXX gfs_acl_get_fh() */
	return (NULL);
}

static int
gfvfs_sys_acl_set_file(vfs_handle_struct *handle, const char *path,
	SMB_ACL_TYPE_T s_type, SMB_ACL_T s_acl)
{
	gfarm_error_t e;
	gfarm_acl_t g_acl;
	gfarm_acl_type_t g_type;
	const char *fullpath;
	static const char diag[] = "sys_acl_set_file";

	fullpath = gfvfs_fullpath(handle, path);
	if (!smb_acl_type_to_gfarm_acl_type(fullpath, diag, s_type, &g_type)) {
		errno = EINVAL;
		return (-1);
	}
	g_acl = gfvfs_smb_acl_to_gfarm_acl(fullpath, s_acl);
	if (g_acl == NULL)
		return (-1); /* with errno */

	e = gfs_acl_set_file(fullpath, g_type, g_acl);
	gfs_acl_free(g_acl);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_acl_set_file: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	gfs_stat_cache_purge(fullpath);
	uncache_parent(fullpath);
	return (0);
}

static int
gfvfs_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
	SMB_ACL_T theacl)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_set_fd(ENOSYS): fsp=%p", fsp);
	errno = ENOSYS; /* XXX gfs_acl_set_fh() */
	return (-1);
}

static int
gfvfs_sys_acl_delete_def_file(vfs_handle_struct *handle,  const char *path)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_delete_def_file: path=%s",
	    path);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_acl_delete_def_file(fullpath);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_acl_delete_def_file: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	gfs_stat_cache_purge(fullpath);
	uncache_parent(fullpath);
	return (0);
}

#if 0 /* unnecessary to hook (transparent) */
static int
gfvfs_sys_acl_get_entry(vfs_handle_struct *handle, SMB_ACL_T theacl,
	int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_get_entry(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_get_tag_type(vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry_d,
	SMB_ACL_TAG_T *tag_type_p)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_get_tag_type(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_get_permset(vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry_d,
	SMB_ACL_PERMSET_T *permset_p)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_get_permset(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static void *
gfvfs_sys_acl_get_qualifier(vfs_handle_struct *handle,
	SMB_ACL_ENTRY_T entry_d)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_get_qualifier(ENOSYS)");
	errno = ENOSYS;
	return (NULL);
}

static int
gfvfs_sys_acl_clear_perms(vfs_handle_struct *handle,  SMB_ACL_PERMSET_T permset)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_clear_perms(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_add_perm(vfs_handle_struct *handle, SMB_ACL_PERMSET_T permset,
	SMB_ACL_PERM_T perm)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_add_perm(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static char *
gfvfs_sys_acl_to_text(vfs_handle_struct *handle, SMB_ACL_T theacl,
	ssize_t *plen)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_to_text(ENOSYS)");
	errno = ENOSYS;
	return (NULL);
}

static SMB_ACL_T
gfvfs_sys_acl_init(vfs_handle_struct *handle, int count)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_init(ENOSYS): count %d",
	    count);
	errno = ENOSYS;
	return (NULL);
}

static int
gfvfs_sys_acl_create_entry(vfs_handle_struct *handle, SMB_ACL_T *pacl,
	SMB_ACL_ENTRY_T *pentry)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_create_entry(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_set_tag_type(vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry,
	SMB_ACL_TAG_T tagtype)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_set_tag_type(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_set_qualifier(vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry,
	void *qual)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_set_qualifier(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_set_permset(vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry,
	SMB_ACL_PERMSET_T permset)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_set_permset(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_valid(vfs_handle_struct *handle, SMB_ACL_T theacl)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_valid(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_get_perm(vfs_handle_struct *handle, SMB_ACL_PERMSET_T permset,
	SMB_ACL_PERM_T perm)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_get_perm(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_free_text(vfs_handle_struct *handle, char *text)
{
	gflog_debug(GFARM_MSG_UNFIXED,
	    "sys_acl_free_text(ENOSYS): text %s", text);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_sys_acl_free_acl(vfs_handle_struct *handle, SMB_ACL_T posix_acl)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_free_acl");
	SAFE_FREE(posix_acl);
	return (0);
}

static int
gfvfs_sys_acl_free_qualifier(vfs_handle_struct *handle, void *qualifier,
	SMB_ACL_TAG_T tagtype)
{
	gflog_debug(GFARM_MSG_UNFIXED, "sys_acl_free_qualifier(ENOSYS)");
	errno = ENOSYS;
	return (-1);
}
#endif /* unnecessary to hook */

static int
gfarm_error_to_errno_for_xattr(gfarm_error_t e)
{
	if (e == GFARM_ERR_NO_SUCH_OBJECT)
		return (ENODATA);
	else
		return (gfarm_error_to_errno(e));
}

static ssize_t
gfvfs_getxattr(vfs_handle_struct *handle, const char *path,
	const char *name, void *value, size_t size)
{
	gfarm_error_t e;
	size_t s = size;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "getxattr: path=%s, name=%s, size=%d",
	    path, name, (int)size);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_getxattr_cached(fullpath, name, value, &s);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_getxattr_cached", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	return (s);
}

static ssize_t
gfvfs_lgetxattr(vfs_handle_struct *handle, const char *path,
	const char *name, void *value, size_t size)
{
	gfarm_error_t e;
	size_t s = size;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "lgetxattr: path=%s, name=%s",
	    path, name);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_lgetxattr_cached(fullpath, name, value, &s);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_lgetxattr_cached", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	return (s);
}

static ssize_t
gfvfs_fgetxattr(vfs_handle_struct *handle,
	struct files_struct *fsp, const char *name, void *value, size_t size)
{
	gfarm_error_t e;
	size_t s = size;

	gflog_debug(GFARM_MSG_UNFIXED, "fgetxattr: fsp=%p, name=%s, size=%d",
	    fsp, name, (int)size);
	e = gfs_fgetxattr((GFS_File)fsp->fh->gen_id, name, value, &s);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_fgetxattr", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	return (s);
}

static ssize_t
gfvfs_listxattr(vfs_handle_struct *handle, const char *path,
	char *list, size_t size)
{
	gfarm_error_t e;
	size_t s = size;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "listxattr: path=%s, size=%d",
	    path, (int)size);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_listxattr(fullpath, list, &s);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_listxattr", e);
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	return (s);
}

static ssize_t
gfvfs_llistxattr(vfs_handle_struct *handle, const char *path,
	char *list, size_t size)
{
	gfarm_error_t e;
	size_t s = size;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "llistxattr: path=%s, size=%d",
	    path, (int)size);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_llistxattr(fullpath, list, &s);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_llistxattr", e);
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	return (s);
}

static ssize_t
gfvfs_flistxattr(vfs_handle_struct *handle,
	struct files_struct *fsp, char *list, size_t size)
{
	gfarm_error_t e;
	size_t s = size;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "flistxattr: fsp=%p, size=%d",
	    fsp, (int)size);
	/* XXX gfs_flistxattr() */
	fullpath = gfvfs_fullpath(handle, fsp->fsp_name->base_name);
	e = gfs_llistxattr(fullpath, list, &s);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_llistxattr", e);
		errno = gfarm_error_to_errno(e);
		return (-1);
	}
	return (0);
}

static int
gfvfs_removexattr(vfs_handle_struct *handle, const char *path,
	const char *name)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "removexattr: path=%s, name=%s",
	    path, name);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_removexattr(fullpath, name);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_removexattr", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	gfs_stat_cache_purge(fullpath);
	uncache_parent(fullpath);
	return (0);
}

static int
gfvfs_lremovexattr(vfs_handle_struct *handle, const char *path,
	const char *name)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "lremovexattr: path=%s, name=%s",
	    path, name);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_lremovexattr(fullpath, name);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_lremovexattr", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	gfs_stat_cache_purge(fullpath);
	uncache_parent(fullpath);
	return (0);
}

static int
gfvfs_fremovexattr(vfs_handle_struct *handle,
	struct files_struct *fsp, const char *name)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED, "fremovexattr: fsp=%p, name=%s",
	    fsp, name);
	e = gfs_fremovexattr((GFS_File)fsp->fh->gen_id, name);
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_fremovexattr", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, fsp->fsp_name->base_name);
	gfs_stat_cache_purge(fullpath);
	uncache_parent(fullpath);
	return (0);
}

static int
xattr_flags_to_gfarm(int flags)
{
	int gflags;

	switch (flags) {
	case XATTR_CREATE:
		gflags = GFS_XATTR_CREATE;
		break;
	case XATTR_REPLACE:
		gflags = GFS_XATTR_REPLACE;
		break;
	default:
		gflags = flags; /* XXX */
		break;
	}
	return (gflags);
}

static int
gfvfs_setxattr(vfs_handle_struct *handle, const char *path,
	const char *name, const void *value, size_t size, int flags)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED,
	    "setxattr: path=%s, name=%s, size=%d, flags=%d",
	    path, name, (int)size, flags);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_setxattr(fullpath, name, value, size,
	    xattr_flags_to_gfarm(flags));
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_setxattr", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	gfs_stat_cache_purge(fullpath);
	uncache_parent(fullpath);
	return (0);
}

static int
gfvfs_lsetxattr(vfs_handle_struct *handle, const char *path,
	const char *name, const void *value, size_t size, int flags)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED,
	    "lsetxattr: path=%s, name=%s, size=%d, flags=%d",
	    path, name, (int)size, flags);
	fullpath = gfvfs_fullpath(handle, path);
	e = gfs_lsetxattr(fullpath, name, value, size,
	    xattr_flags_to_gfarm(flags));
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_lsetxattr", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	gfs_stat_cache_purge(fullpath);
	uncache_parent(fullpath);
	return (0);
}

static int
gfvfs_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
	const char *name, const void *value, size_t size, int flags)
{
	gfarm_error_t e;
	const char *fullpath;

	gflog_debug(GFARM_MSG_UNFIXED,
	    "fsetxattr: fsp=%p, name=%s, size=%d, flags=%d",
	    fsp, name, (int)size, flags);
	e = gfs_fsetxattr((GFS_File)fsp->fh->gen_id, name, value, size,
	    xattr_flags_to_gfarm(flags));
	if (e != GFARM_ERR_NO_ERROR) {
		gfvfs_error(GFARM_MSG_UNFIXED, "gfs_fsetxattr", e);
		errno = gfarm_error_to_errno_for_xattr(e);
		return (-1);
	}
	fullpath = gfvfs_fullpath(handle, fsp->fsp_name->base_name);
	gfs_stat_cache_purge(fullpath);
	uncache_parent(fullpath);
	return (0);
}

static int
gfvfs_aio_read(struct vfs_handle_struct *handle, struct files_struct *fsp,
	SMB_STRUCT_AIOCB *aiocb)
{
	gflog_debug(GFARM_MSG_UNFIXED, "aio_read(ENOSYS): fsp=%p", fsp);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_aio_write(struct vfs_handle_struct *handle, struct files_struct *fsp,
	SMB_STRUCT_AIOCB *aiocb)
{
	gflog_debug(GFARM_MSG_UNFIXED, "aio_write(ENOSYS): fsp=%p", fsp);
	errno = ENOSYS;
	return (-1);
}

static ssize_t
gfvfs_aio_return_fn(struct vfs_handle_struct *handle,
	struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb)
{
	gflog_debug(GFARM_MSG_UNFIXED, "aio_return_fn(ENOSYS): fsp=%p", fsp);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_aio_cancel(struct vfs_handle_struct *handle,
	struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb)
{
	gflog_debug(GFARM_MSG_UNFIXED, "aio_cancel(ENOSYS): fsp=%p", fsp);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_aio_error_fn(struct vfs_handle_struct *handle,
	struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb)
{
	gflog_debug(GFARM_MSG_UNFIXED, "aio_error_fn(ENOSYS): fsp=%p", fsp);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_aio_fsync(struct vfs_handle_struct *handle, struct files_struct *fsp,
	int op, SMB_STRUCT_AIOCB *aiocb)
{
	gflog_debug(GFARM_MSG_UNFIXED, "aio_fsync(ENOSYS): fsp=%p, op=%d",
	    fsp, op);
	errno = ENOSYS;
	return (-1);
}

static int
gfvfs_aio_suspend(struct vfs_handle_struct *handle, struct files_struct *fsp,
	const SMB_STRUCT_AIOCB * const aiocb[], int n,
	const struct timespec *ts)
{
	gflog_debug(GFARM_MSG_UNFIXED, "aio_suspend(ENOSYS): fsp=%p, n_cb=%d",
	    fsp, n);
	errno = ENOSYS;
	return (-1);
}

static bool
gfvfs_aio_force(struct vfs_handle_struct *handle, struct files_struct *fsp)
{
	gflog_debug(GFARM_MSG_UNFIXED, "aio_force(ENOSYS): fsp=%p", fsp);
	errno = ENOSYS;
	return (false);
}

static bool
gfvfs_is_offline(struct vfs_handle_struct *handle,
	const struct smb_filename *fname, SMB_STRUCT_STAT *sbuf)
{
	gflog_debug(GFARM_MSG_UNFIXED, "is_offline(ENOSYS): path=%s%s",
	    fname->base_name,
	    fname->stream_name != NULL ? fname->stream_name : "");
	errno = ENOSYS;
	return (false);
}

static int
gfvfs_set_offline(struct vfs_handle_struct *handle,
	const struct smb_filename *fname)
{
	gflog_debug(GFARM_MSG_UNFIXED, "set_offline(ENOSYS): path=%s%s",
	    fname->base_name,
	    fname->stream_name != NULL ? fname->stream_name : "");
	errno = ENOSYS;
	return (false);
}

/* VFS operations structure */

struct vfs_fn_pointers vfs_gfarm_fns = {
	/* Disk operations */
	.connect_fn = gfvfs_connect,
	.disconnect = gfvfs_disconnect,
	.disk_free = gfvfs_disk_free,
	.get_quota = gfvfs_get_quota, /* ENOSYS */
	.set_quota = gfvfs_set_quota, /* ENOSYS */
	.get_shadow_copy_data = gfvfs_get_shadow_copy_data, /* ENOSYS */
	.statvfs = gfvfs_statvfs,
	.fs_capabilities = gfvfs_fs_capabilities, /* noop */

	/* Directory operations */
	.opendir = gfvfs_opendir,
	.fdopendir = gfvfs_fdopendir, /* ENOSYS, it's OK */
	.readdir = gfvfs_readdir,
	.seekdir = gfvfs_seekdir,
	.telldir = gfvfs_telldir,
	.rewind_dir = gfvfs_rewind_dir,
	.mkdir = gfvfs_mkdir,
	.rmdir = gfvfs_rmdir,
	.closedir = gfvfs_closedir,
	.init_search_op = gfvfs_init_search_op, /* noop */

	/* File operations */
	.open_fn = gfvfs_open,
	.create_file = gfvfs_create_file, /* transparent */
	.close_fn = gfvfs_close_fn,
	.vfs_read = gfvfs_vfs_read,
	.pread = gfvfs_pread,
	.write = gfvfs_write,
	.pwrite = gfvfs_pwrite,
	.lseek = gfvfs_lseek,
	.sendfile = gfvfs_sendfile, /* ENOSYS */
	.recvfile = gfvfs_recvfile, /* ENOSYS */
	.rename = gfvfs_rename,
	.fsync = gfvfs_fsync,
	.stat = gfvfs_stat,
	.fstat = gfvfs_fstat,
	.lstat = gfvfs_lstat,
	.get_alloc_size = gfvfs_get_alloc_size,
	.unlink = gfvfs_unlink,
	.chmod = gfvfs_chmod,
	.fchmod = gfvfs_fchmod, /* ENOSYS */
	.chown = gfvfs_chown, /* ENOSYS */
	.fchown = gfvfs_fchown, /* ENOSYS */
	.lchown = gfvfs_lchown, /* ENOSYS */
	.chdir = gfvfs_chdir,
	.getwd = gfvfs_getwd,
	.ntimes = gfvfs_ntimes,
	.ftruncate = gfvfs_ftruncate,
	.fallocate = gfvfs_fallocate, /* ENOSYS */
	.lock = gfvfs_lock, /* ENOSYS */
	.kernel_flock = gfvfs_kernel_flock, /* ignored */
	.linux_setlease = gfvfs_linux_setlease, /* ENOSYS */
	.getlock = gfvfs_getlock, /* ENOSYS */
	.symlink = gfvfs_symlink,
	.vfs_readlink = gfvfs_vfs_readlink,
	.link = gfvfs_link,
	.mknod = gfvfs_mknod, /* incomplete */
	.realpath = gfvfs_realpath,
	.notify_watch = gfvfs_notify_watch, /* ENOSYS */
	.chflags = gfvfs_chflags, /* ENOSYS */
	.file_id_create = gfvfs_file_id_create,

	.streaminfo = gfvfs_streaminfo, /* transparent */
	.get_real_filename = gfvfs_get_real_filename, /* EOPNOTSUPP */
	.connectpath = gfvfs_connectpath, /* transparent */
	.brl_lock_windows = gfvfs_brl_lock_windows, /* transparent */
	.brl_unlock_windows = gfvfs_brl_unlock_windows, /* transparent */
	.brl_cancel_windows = gfvfs_brl_cancel_windows, /* transparent */
	.strict_lock = gfvfs_strict_lock, /* transparent */
	.strict_unlock = gfvfs_strict_unlock, /* transparent */
	.translate_name = gfvfs_translate_name, /* NONE_MAPPED */

	/* NT ACL operations */
	.fget_nt_acl = gfvfs_fget_nt_acl, /* transparent */
	.get_nt_acl = gfvfs_get_nt_acl, /* transparent */
	.fset_nt_acl = gfvfs_fset_nt_acl, /* transparent */

	/* POSIX ACL operations */
	.chmod_acl = gfvfs_chmod_acl,
	.fchmod_acl = gfvfs_fchmod_acl,
	.sys_acl_get_file = gfvfs_sys_acl_get_file,
	.sys_acl_get_fd = gfvfs_sys_acl_get_fd, /* ENOSYS */
	.sys_acl_set_file = gfvfs_sys_acl_set_file,
	.sys_acl_set_fd = gfvfs_sys_acl_set_fd, /* ENOSYS */
	.sys_acl_delete_def_file = gfvfs_sys_acl_delete_def_file,
#if 0 /* unnecessary to hook */
	.sys_acl_get_entry = gfvfs_sys_acl_get_entry,
	.sys_acl_get_tag_type = gfvfs_sys_acl_get_tag_type,
	.sys_acl_get_permset = gfvfs_sys_acl_get_permset,
	.sys_acl_get_qualifier = gfvfs_sys_acl_get_qualifier,
	.sys_acl_clear_perms = gfvfs_sys_acl_clear_perms,
	.sys_acl_add_perm = gfvfs_sys_acl_add_perm,
	.sys_acl_to_text = gfvfs_sys_acl_to_text,
	.sys_acl_init = gfvfs_sys_acl_init,
	.sys_acl_create_entry = gfvfs_sys_acl_create_entry,
	.sys_acl_set_tag_type = gfvfs_sys_acl_set_tag_type,
	.sys_acl_set_qualifier = gfvfs_sys_acl_set_qualifier,
	.sys_acl_set_permset = gfvfs_sys_acl_set_permset,
	.sys_acl_valid = gfvfs_sys_acl_valid,
	.sys_acl_get_perm = gfvfs_sys_acl_get_perm,
	.sys_acl_free_text = gfvfs_sys_acl_free_text,
	.sys_acl_free_acl = gfvfs_sys_acl_free_acl,
	.sys_acl_free_qualifier = gfvfs_sys_acl_free_qualifier,
#endif /* unnecessary to hook */

	/* EA operations */
	.getxattr = gfvfs_getxattr,
	.lgetxattr = gfvfs_lgetxattr,
	.fgetxattr = gfvfs_fgetxattr,
	.listxattr = gfvfs_listxattr,
	.llistxattr = gfvfs_llistxattr,
	.flistxattr = gfvfs_flistxattr,
	.removexattr = gfvfs_removexattr,
	.lremovexattr = gfvfs_lremovexattr,
	.fremovexattr = gfvfs_fremovexattr,
	.setxattr = gfvfs_setxattr,
	.lsetxattr = gfvfs_lsetxattr,
	.fsetxattr = gfvfs_fsetxattr,

	/* aio operations */  /* ENOSYS */
	.aio_read = gfvfs_aio_read,
	.aio_write = gfvfs_aio_write,
	.aio_return_fn = gfvfs_aio_return_fn,
	.aio_cancel = gfvfs_aio_cancel,
	.aio_error_fn = gfvfs_aio_error_fn,
	.aio_fsync = gfvfs_aio_fsync,
	.aio_suspend = gfvfs_aio_suspend,
	.aio_force = gfvfs_aio_force,

	/* offline operations */  /* ENOSYS */
	.is_offline = gfvfs_is_offline,
	.set_offline = gfvfs_set_offline
};

NTSTATUS init_samba_module(void)
{
	return (smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "gfarm",
	    &vfs_gfarm_fns));
}
