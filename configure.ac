#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([gfarm_samba], [1.0.1])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([gfarm.c])
AC_CONFIG_HEADERS([config_gfarm.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

### --with-gfarm=GFARM
AC_MSG_CHECKING([for Gfarm file system])
AC_ARG_WITH([gfarm],
  AC_HELP_STRING([--with-gfarm=PATH], [path to gfarm file system [[/usr]]]))
case x$with_gfarm in
  x|xyes|xno) GFARM=/usr ;;
  *) GFARM=$with_gfarm ;;
esac
if test x"$GFARM" != x/usr; then
  CPPFLAGS="$CPPFLAGS -I$GFARM/include"
  LDFLAGS="$LDFLAGS -L$GFARM/lib"
fi
AC_MSG_RESULT([$GFARM])

### --with-samba=SAMBA
AC_MSG_CHECKING([for Samba])
AC_ARG_WITH([samba],
  AC_HELP_STRING([--with-samba=PATH], [path to sambe source [[/usr/src/samba/source3]]]))
case x$with_samba in
  x|xyes|xno) SAMBA=/usr/src/samba/source3 ;;
  *) SAMBA=$with_samba ;;
esac
if test x"$SAMBA" != x/usr; then
  CPPFLAGS="$CPPFLAGS -I$SAMBA/include -I$SAMBA/../lib/replace -I$SAMBA -I$SAMBA/.. -I$SAMBA/../lib/talloc -I$SAMBA/../lib/tevent"
  LDFLAGS="$LDFLAGS -L$SAMBA/lib"
fi
AC_MSG_RESULT([$SAMBA])

# Checks for libraries.
AC_CHECK_LIB([gfarm], [gfarm_initialize],, [AC_MSG_ERROR([libgfarm not found.  Use --with-gfarm option])])
AC_CHECK_LIB([gfarm], [gfs_statdir],, [AC_MSG_ERROR([Gfarm-2.5.4 or later is required])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h unistd.h])
AC_CHECK_HEADERS([gfarm/gfarm.h],, [AC_MSG_ERROR([gfarm/gfarm.h not found])])

# Samba includes.h cannot be checked by AC_CHECK_HEADERS
AC_MSG_CHECKING([Samba includes.h])
AC_TRY_COMPILE([#include "includes.h"],[],,
[AC_MSG_ERROR([Samba include files not found. Use --with-samba option to specify the samba source directory])])
AC_MSG_RESULT([yes])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strdup strerror])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
