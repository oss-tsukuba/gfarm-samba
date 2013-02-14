/*
 * $Id$
 */

#include "includes.h"

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#include <gfarm/gfarm.h>

#include "gfarm_id.h"

void
gfvfs_acl_id_init()
{
	static int initialized = 0;

	if (initialized == 0) {
		gfarm_id_init(70000, 79999, 70000, 79999, 0);
		initialized = 1;
	}
}

static bool
acl_gfarm_ace_to_smb_ace(
	const char *path, gfarm_acl_entry_t g_ace, struct smb_acl_entry *s_ace)
{
	gfarm_error_t e;
	gfarm_acl_tag_t tag;
	gfarm_acl_permset_t permset;
	char *name;
	uid_t uid;
	gid_t gid;
	int b;

	(void)gfs_acl_get_tag_type(g_ace, &tag);
	switch (tag) {
	case GFARM_ACL_USER:
		s_ace->a_type = SMB_ACL_USER;
		break;
	case GFARM_ACL_USER_OBJ:
		s_ace->a_type = SMB_ACL_USER_OBJ;
		break;
	case GFARM_ACL_GROUP:
		s_ace->a_type = SMB_ACL_GROUP;
		break;
	case GFARM_ACL_GROUP_OBJ:
		s_ace->a_type = SMB_ACL_GROUP_OBJ;
		break;
	case GFARM_ACL_OTHER:
		s_ace->a_type = SMB_ACL_OTHER;
		break;
	case GFARM_ACL_MASK:
		s_ace->a_type = SMB_ACL_MASK;
		break;
	default:
		gflog_error(GFARM_MSG_UNFIXED,
		    "unknown tag: type=%u", (unsigned int)tag);
		errno = EINVAL;
		return (False);
	}

	switch (s_ace->a_type) {
	case SMB_ACL_USER:
		(void)gfs_acl_get_qualifier(g_ace, &name);
		e = gfarm_id_user_to_uid(path, name, &uid);
		if (e != GFARM_ERR_NO_ERROR) {
			gflog_error(GFARM_MSG_UNFIXED,
			    "gfarm_id_user_to_uid: %s", gfarm_error_string(e));
			errno = gfarm_error_to_errno(e);
			return (False);
		}
		s_ace->uid = uid;
		break;
	case SMB_ACL_GROUP:
		(void)gfs_acl_get_qualifier(g_ace, &name);
		e = gfarm_id_group_to_gid(path, name, &gid);
		if (e != GFARM_ERR_NO_ERROR) {
			gflog_error(GFARM_MSG_UNFIXED,
			    "gfarm_id_group_to_gid: %s",
			    gfarm_error_string(e));
			errno = gfarm_error_to_errno(e);
			return (False);
		}
		s_ace->gid = gid;
		break;
	default:
		break;
	}
	(void)gfs_acl_get_permset(g_ace, &permset);
	s_ace->a_perm = 0;

	(void)gfs_acl_get_perm(permset, GFARM_ACL_READ, &b);
	if (b)
		s_ace->a_perm |= SMB_ACL_READ;

	(void)gfs_acl_get_perm(permset, GFARM_ACL_WRITE, &b);
	if (b)
		s_ace->a_perm |= SMB_ACL_WRITE;

	(void)gfs_acl_get_perm(permset, GFARM_ACL_EXECUTE, &b);
	if (b)
		s_ace->a_perm |= SMB_ACL_EXECUTE;

	return (True);
}

SMB_ACL_T
gfvfs_gfarm_acl_to_smb_acl(const char *path, gfarm_acl_t acl)
{
	gfarm_error_t e;
	SMB_ACL_T s_acl = SMB_MALLOC_P(struct smb_acl_t), tmp;
	gfarm_acl_entry_t ent;
	int save_errno;

	if (s_acl == NULL) {
		gflog_error(GFARM_MSG_UNFIXED,
		    "gfarm_acl_to_smb_acl: no memory");
		errno = ENOMEM;
		return (NULL);
	}
	ZERO_STRUCTP(s_acl);
	e = gfs_acl_get_entry(acl, GFARM_ACL_FIRST_ENTRY, &ent);
	while (e == GFARM_ERR_NO_ERROR) {
		tmp = SMB_REALLOC(s_acl, sizeof(struct smb_acl_t) +
		    (sizeof(struct smb_acl_entry) * (s_acl->count + 1)));
		if (tmp == NULL) {
			SAFE_FREE(s_acl);
			gflog_error(GFARM_MSG_UNFIXED,
			    "gfarm_acl_to_smb_acl: no memory");
			errno = ENOMEM;
			return (NULL);
		}
		s_acl = tmp;
		if (!acl_gfarm_ace_to_smb_ace(path, ent,
		    &s_acl->acl[s_acl->count])) {
			save_errno = errno;
			SAFE_FREE(s_acl);
			errno = save_errno;
			return (NULL);
		}
		s_acl->count += 1;
		e = gfs_acl_get_entry(acl, GFARM_ACL_NEXT_ENTRY, &ent);
	}
	if (e == GFARM_ERR_NO_SUCH_OBJECT)
		e = GFARM_ERR_NO_ERROR;
	if (e != GFARM_ERR_NO_ERROR) {
		SAFE_FREE(s_acl);
		errno = gfarm_error_to_errno(e);
		return (NULL);
	}
	return (s_acl);
}

static void
set_mode_smb_to_gfarm(gfarm_acl_entry_t entry, SMB_ACL_PERM_T perm)
{
	gfarm_acl_permset_t permset;

	gfs_acl_get_permset(entry, &permset);
	gfs_acl_clear_perms(permset);
	if (perm & SMB_ACL_READ)
		gfs_acl_add_perm(permset, GFARM_ACL_READ);
	if (perm & SMB_ACL_WRITE)
		gfs_acl_add_perm(permset, GFARM_ACL_WRITE);
	if (perm & SMB_ACL_EXECUTE)
		gfs_acl_add_perm(permset, GFARM_ACL_EXECUTE);
	gfs_acl_set_permset(entry, permset);
}

gfarm_acl_t
gfvfs_smb_acl_to_gfarm_acl(const char *path, SMB_ACL_T s_acl)
{
	gfarm_error_t e;
	gfarm_acl_t g_acl;
	int i;
	char *name;

	e = gfs_acl_init(s_acl->count, &g_acl);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED, "gfs_acl_init: %s",
		    gfarm_error_string(e));
		errno = gfarm_error_to_errno(e);
		return (NULL);
	}
	for (i = 0; i < s_acl->count; i++) {
		const struct smb_acl_entry *entry = &s_acl->acl[i];
		gfarm_acl_entry_t ent;
		gfarm_acl_tag_t tag;

		e = gfs_acl_create_entry(&g_acl, &ent);
		if (e != GFARM_ERR_NO_ERROR) {
			gflog_error(GFARM_MSG_UNFIXED,
			   "gfs_acl_create_entry: %s", gfarm_error_string(e));
			goto fail;
		}
		switch (entry->a_type) {
		case SMB_ACL_USER:
			tag = GFARM_ACL_USER;
			break;
		case SMB_ACL_USER_OBJ:
			tag = GFARM_ACL_USER_OBJ;
			break;
		case SMB_ACL_GROUP:
			tag = GFARM_ACL_GROUP;
			break;
		case SMB_ACL_GROUP_OBJ:
			tag = GFARM_ACL_GROUP_OBJ;
			break;
		case SMB_ACL_OTHER:
			tag = GFARM_ACL_OTHER;
			break;
		case SMB_ACL_MASK:
			tag = GFARM_ACL_MASK;
			break;
		default:
			gflog_error(GFARM_MSG_UNFIXED,
			    "unknown tag value %d", entry->a_type);
			e = GFARM_ERR_INVALID_ARGUMENT;
			goto fail;
		}
		gfs_acl_set_tag_type(ent, tag);

		switch (entry->a_type) {
		case SMB_ACL_USER:
			e = gfarm_id_uid_to_user(path, entry->uid, &name);
			if (e != GFARM_ERR_NO_ERROR) {
				gflog_error(GFARM_MSG_UNFIXED,
				    "gfarm_id_uid_to_user: %s",
				    gfarm_error_string(e));
				goto fail;
			}
			gfs_acl_set_qualifier(ent, name);
			break;
		case SMB_ACL_GROUP:
			e = gfarm_id_gid_to_group(path, entry->gid, &name);
			if (e != GFARM_ERR_NO_ERROR) {
				gflog_error(GFARM_MSG_UNFIXED,
				    "gfarm_id_gid_to_group: %s",
				    gfarm_error_string(e));
				goto fail;
			}
			gfs_acl_set_qualifier(ent, name);
			break;
		default:
			gfs_acl_set_qualifier(ent, NULL);
			break;
		}
		set_mode_smb_to_gfarm(ent, entry->a_perm);
	}
	gfs_acl_sort(g_acl);
	e = gfs_acl_valid(g_acl);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_UNFIXED,
		    "ACL is invalid for set: %s", gfarm_error_string(e));
		goto fail;
	}
	return (g_acl);
fail:
	gfs_acl_free(g_acl);
	errno = gfarm_error_to_errno(e);
	return (NULL);
}
