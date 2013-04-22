ACLOCAL_AMFLAGS = -I m4
nobase_lib_LTLIBRARIES = vfs/gfarm.la
vfs_gfarm_la_SOURCES = gfarm.c gfarm_acl.c gfarm_acl.h gfarm_id.c gfarm_id.h gfarm_hash.h msgno/msgno.h
vfs_gfarm_la_LDFLAGS = -module
AM_CFLAGS = -Wall
EXTRA_DIST = README

# gflog message number assignment
ASSIGNMSGNO=$(top_srcdir)/msgno/assign_msgno.pl

.PHONY: msgno
msgno:
	GFARM_TOPDIR=$(top_srcdir) $(ASSIGNMSGNO) $(vfs_gfarm_la_SOURCES)
