AC_INIT([stream-security-httpd], [1.0.4], [support@entwinemedia.com])
AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_CHECK_PROG([HAVE_APXS], [apxs], yes)
if test x"$HAVE_APXS" != x"yes" ; then
    AC_MSG_ERROR([Please install apxs before installing.])
fi

AC_CHECK_PROG([HAVE_LIBTOOL], [libtool], yes)
if test x"$HAVE_LIBTOOL" != x"yes" ; then
    AC_MSG_ERROR([Please install libtool before installing.])
fi

AC_PROG_LIBTOOL

AC_CHECK_PROG([HAVE_AR], [ar], yes)
if test x"$HAVE_AR" != x"yes" ; then
    AC_MSG_ERROR([Please install ar before installing.])
fi

AC_CHECK_LIB([jansson], [json_object_get], [], [
              AC_MSG_ERROR([unable to find the json_object_get() function in jansson library, is jansson installed?])
])

AC_CHECK_LIB([crypto], [BIO_new_mem_buf], [], [
              AC_MSG_ERROR([unable to find the BIO_new_mem_buf() function in the openssl library, is openssh installed?])
])

AC_DEFUN([APACHE_DIR],[

  AC_ARG_WITH(
    apache,
    [  --with-apache[=DIR]     Apache server directory],
    ,
    [with_apache="/usr/include/httpd"]
  )

  AC_MSG_CHECKING(for Apache directory)

  if test "$with_apache" = "no"; then
    AC_MSG_ERROR( Specify the apache using --with-apache)
  else
    if test -e $with_apache/httpd.h; then
      apache_dir=$with_apache
      AC_MSG_RESULT(APACHE found!)
    else
      AC_MSG_ERROR( httpd.h not found in $with_apache, you will need to specify the correct location using --with-apache. )
    fi
  fi

])

APACHE_DIR
AC_SUBST(apache_dir)

AC_DEFUN([APR_DIR],[

  AC_ARG_WITH(
    apr,
    [  --with-apr[=DIR]     Apache Portable Runtime directory],
    ,
    [with_apr="/usr/include/apr-1"]
  )

  AC_MSG_CHECKING(for Apache Portable Runtime directory)

  if test "$with_apr" = "no"; then
    AC_MSG_ERROR( Specify the Apache Portable Runtime directory using --with-apr)
  else
    if test -e $with_apr/apr.h; then
      apr_dir=$with_apr
      AC_MSG_RESULT(APACHE Portable Runtime directory found!)
    else
      AC_MSG_ERROR( apr.h not found in $with_apr, you will need to specify the correct location using --with-apr. )
    fi
  fi

])

APR_DIR
AC_SUBST(apr_dir)

AC_OUTPUT(Makefile)
