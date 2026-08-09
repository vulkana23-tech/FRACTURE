#ifndef FRACTURE_ZABBIX_CONFIG_H
#define FRACTURE_ZABBIX_CONFIG_H
/* config.h minimo hecho a mano para este harness -- FRACTURE, no parte
   del build oficial de Zabbix (que usa autotools ./configure). Solo
   declara HAVE_*_H para headers POSIX/glibc realmente presentes en
   este Linux, replicando lo que ./configure detectaria en este mismo
   sistema -- no inventa capacidades que no existen. */
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_ASSERT_H 1
#define HAVE_ERRNO_H 1
#define HAVE_STDARG_H 1
#define HAVE_CTYPE_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_STRING_H 1
#define HAVE_STRINGS_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TIMES_H 1
#define HAVE_FCNTL_H 1
#define HAVE_NETDB_H 1
#define HAVE_SYS_WAIT_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_PWD_H 1
#define HAVE_SIGNAL_H 1
#define HAVE_STDINT_H 1
#define HAVE_PTHREAD_H 1
#define HAVE_RESOLV_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_STATVFS_H 1
#define HAVE_SYS_RESOURCE_H 1
#define HAVE_SYSLOG_H 1
#define HAVE_TIME_H 1
#define HAVE_UNISTD_H 1
#define HAVE_MATH_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_SYS_TIMEB_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_STDDEF_H 1
#define HAVE_LIMITS_H 1
#define HAVE_FLOAT_H 1
#define HAVE_SYS_UTSNAME_H 1
#define HAVE_POLL_H 1
#define HAVE_MALLOC_H 1
#define HAVE_LIBGEN_H 1
#define HAVE_STDATOMIC_H 1
#define HAVE_SETJMP_H 1
#define HAVE_SYS_SYSMACROS_H 1
#define HAVE_SYS_UCONTEXT_H 1
#endif
