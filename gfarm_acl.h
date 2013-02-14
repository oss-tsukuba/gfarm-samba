/*
 * $Id$
 */

void gfvfs_acl_id_init();
SMB_ACL_T gfvfs_gfarm_acl_to_smb_acl(const char *, gfarm_acl_t);
gfarm_acl_t gfvfs_smb_acl_to_gfarm_acl(const char *, SMB_ACL_T);
