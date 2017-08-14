dnl Licensed to The Apereo Foundation under one or more contributor license
dnl agreements. See the NOTICE file distributed with this work for additional
dnl information regarding copyright ownership.

dnl The Apereo Foundation licenses this file to you under the Educational
dnl Community License, Version 2.0 (the "License"); you may not use this file
dnl except in compliance with the License. You may obtain a copy of the License
dnl at:

dnl   http://opensource.org/licenses/ecl2.txt

dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
dnl WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
dnl License for the specific language governing permissions and limitations under
dnl the License.

dnl Process this file with autoconf to produce a configure script.

AC_INIT([stream-security-httpd], [1.0.5], [support@entwinemedia.com])

AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of the apxs executable [[apxs]]]),
            [APXS="$with_apxs"])

if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, [apxs],
                   [$PATH:/usr/local/apache/bin:/usr/sbin])
fi

AC_CHECK_LIB([jansson], [json_object_get], [], [
              AC_MSG_ERROR([unable to find the json_object_get() function in jansson library, is jansson installed?])
])

AC_CHECK_LIB([crypto], [BIO_new_mem_buf], [], [
              AC_MSG_ERROR([unable to find the BIO_new_mem_buf() function in the openssl library, is openssh installed?])
])

XCODE_PREFIX="/Applications/Xcode.app/Contents/Developer/Toolchains/"
XCODE_CC="${XCODE_PREFIX}XcodeDefault.xctoolchain/usr/bin/cc"
XCODE_BIN_PATTERN="${XCODE_PREFIX}.*/usr/bin/"

if test -x "${APXS}"; then
    APXS_CC=`${APXS} -q CC`
    APXS_LIBTOOL=`${APXS} -q LIBTOOL | sed -e "s/ .*$//"`
    if [[[ ${APXS_CC} = ${XCODE_PREFIX}* ]]]; then
        if test ! -x ${XCODE_CC}; then
            cat "${APXS_LIBTOOL}" | sed -e \
                "s%${XCODE_BIN_PATTERN}%/usr/bin/%" > ./libtool
            cat "${APXS}" | sed -e "s%get_vars(\"CC\")%\"/usr/bin/cc\"%" \
                -e 's%^my $libtool = .*;%my $libtool = \"./libtool\";%' > ./apxs
        else
            cat "${APXS_LIBTOOL}" | sed -e \
                "s%OSX10.[[0-9]][[0-9]]*.xctoolchain%XcodeDefault.xctoolchain%" > ./libtool
            cat "${APXS}" | sed -e "s%get_vars(\"CC\")%\"${XCODE_CC}\"%" \
                -e 's%^my $libtool = .*;%my $libtool = \"./libtool\";%' > ./apxs
        fi

        chmod +x ./apxs ./libtool
        APXS=./apxs
    fi
fi

AC_SUBST(APXS)

AC_CHECK_FUNCS(prctl)

AC_MSG_CHECKING(Apache version)
HTTPD="`${APXS} -q SBINDIR`/`${APXS} -q TARGET`"
HTTPD_INCLUDEDIR="`${APXS} -q INCLUDEDIR`"
if test -x ${HTTPD}; then
    HTTPD_VERSION=`${HTTPD} -v | awk '/version/ {print $3}' \
     | awk -F/ '{print $2}'`
else
    if test -f ${HTTPD_INCLUDEDIR}/ap_release.h; then
        HTTPD_VERSION=`grep '^#define AP_SERVER_MAJORVERSION_NUMBER ' \
         ${HTTPD_INCLUDEDIR}/ap_release.h | sed -e \
         's/^#define AP_SERVER_MAJORVERSION_NUMBER \([0-9]\).*/\1.X/'`
    else
        if test -f ${HTTPD_INCLUDEDIR}/httpd.h; then
            HTTPD_VERSION=`grep '^#define APACHE_RELEASE ' \
             ${HTTPD_INCLUDEDIR}/httpd.h | sed -e \
             's/^#define APACHE_RELEASE \([0-9]\).*/\1.X/'`
        else
            HTTPD_VERSION="2.?"
        fi
    fi
fi
AC_MSG_RESULT($HTTPD_VERSION)

LDLIBS1=-ljansson
LDLIBS2=-lcrypto

LDLIBS="${LDLIBS} ${LDLIBS1} ${LDLIBS2}"

AC_SUBST(LDLIBS)
AC_SUBST(DESTDIR)

LIBEXECDIR="`${APXS} -q LIBEXECDIR`"
AC_SUBST(LIBEXECDIR)

HTTPD_MAJOR_VERSION=`echo ${HTTPD_VERSION} | sed -e 's/\..*//'`

AC_OUTPUT(Makefile)
