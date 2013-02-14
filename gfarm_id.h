/*
 * $Id$
 */

gfarm_error_t gfarm_id_init(
	gfarm_uint32_t, gfarm_uint32_t, gfarm_uint32_t, gfarm_uint32_t, int);

gfarm_error_t gfarm_id_user_to_uid(const char *, const char *, uid_t *);
gfarm_error_t gfarm_id_group_to_gid(const char *, const char *, gid_t *);
gfarm_error_t gfarm_id_uid_to_user(const char *, uid_t, char **);
gfarm_error_t gfarm_id_gid_to_group(const char *, gid_t, char **);

uid_t gfarm_id_nobody_uid(void);
gid_t gfarm_id_nogroup_gid(void);
