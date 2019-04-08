#!/bin/sh
# Filename: certreq.sh
# Location: atower201:/etc/ansible/roles/certreq/files/certreq.sh
# Author: bgstack15@gmail.com
# Startdate: 2017-11-17 09:13:53
# Title: Script that Requests a Certificate from a Microsoft Sub-CA
# Purpose: Automate host certificate generation in a domain environment
# Package: ansible role certreq
# History:
#    2017-11-22 Add ca cert chain
#    2018-04-16 Add --list and --csr options
#    2018-05-07 Add actions for using a CA with manually-approved certs
#    2018-06-19 Fix get number of ca cert
#    2018-07-30 add error checking on the request and authorization
#    2018-08-16 update error checking and exit codes
#    2018-09-10 add CERTREQ_OPENSSL_BIN and CERTREQ_OPENSSL_CONF values, and SAN support
# Usage: in ansible role certreq
#    Microsoft CA cert templates have permissions on them. A user must be able to "enroll" on the template.
# Reference: ftemplate.sh 2017-10-10x; framework.sh 2017-10-09a
#    fundamental curl statements https://stackoverflow.com/questions/31283476/submitting-base64-csr-to-a-microsoft-ca-via-curl/39722983#39722983
#    subjectaltname in openssl.cnf https://bgstack15.wordpress.com/2017/05/21/generate-certificate-with-subjectaltname-attributes-in-freeipa/
# Improve:
fiversion="2017-10-10x"
certreqversion="2018-09-10b"

usage() {
   less -F >&2 <<ENDUSAGE
usage: certreq.sh [-dhV] [-u username] [-p password] [-w tempdir] [-t template] [--cn CN] [--ca <CA hostname>] [-l|-g] [--list|--csr /path/to/file|--fetch|--request] [--no-ca] [--reqid <reqid_string>] [--openssl-bin /bin/openssl] [--openssl-conf /opt/openssl.cnf]
version ${certreqversion}
 -d debug   Show debugging info, including parsed variables.
 -h usage   Show this usage block.
 -V version Show script version number.
 -u username User to connect via ntlm to CA. Can be "username" or "domain\\username"
 -p password
 -w workdir  Temp directory to work in. Default is \$(mktemp -d).
 -t template Template to request from CA. Default is "ConfigMgrLinuxClientCertificate"
 --cn        CN to request. Default is \$( hostname -f )
 --ca        CA hostname or base URL. Example: ca2.example.com
 --reqid <value>  Request ID. Needed by --fetch action.
 --no-ca     Skip downloading the CA cert chain.
 --openssl-bin  <value>  Use this binary for openssl. Default is "openssl"
 --openssl-conf <value>  Use this config for openssl. Default is none.
 --dnssans <value>  Use a pipe-delimited set of values as subjectAltName dns entries.
 --ipsans <value>  Use a pipe-delimited set of values as subjectAltName ip entries.
ACTIONS:
 --list      list available templates and exit.
 --csr filename Provide a .csr file instead of making a new csr. Accepts "stdin" to read from standard in.
 --fetch     Only retrieve a cert that was previously requested. Requires CERTREQ_REQID or --reqid.
 --request   Only request a cert. Use if the cert needs to be approved manually by an admin on the server.
Return values under 1000: A non-zero value is the sum of the items listed here:
 0 Everything worked
 1 interaction with website failed: invalid login credentials or curl returned non-zero value
 2 cert request denied
 4 invalid cert file: incomplete cert file, or no issuer
Return values above 1000:
1001 Help or version info displayed
1002 Count or type of flaglessvals is incorrect
1003 Incorrect OS type
1004 Unable to find dependency
1005 Not run as root or sudo
1006 Input is invalid
ENDUSAGE
}

# DEFINE FUNCTIONS

openssl_req() {
   # call: openssl_req "${CERTREQ_CNPARAM}" "${CERTREQ_SUBJECT}" "${CERTREQ_ACTION}" "${CERTREQ_CSR}" "${CERTREQ_OPENSSL_BIN}" "${CERTREQ_openssl_config}"
   # outputs:
   #    vars: ${CSR} ${DATA} ${CERTATTRIB}
   #    files: ${CERTREQ_WORKDIR}/${this_filename}.crt ${CERTREQ_WORKDIR}/${thisfilename}.key
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_filename="${1}"
   local this_subject="${2}"
   local this_action="${3}"
   local this_csr="${4}"
   local this_openssl_bin="${5}"
   local this_openssl_config="${6}"

   debuglev 8 && echo "Action ${this_action}"
   case "${this_action}" in
      *-csr)
         case "${this_csr}" in
            stdin)
               cat - > "${CERTREQ_WORKDIR}/${this_filename}.csr"
               ;;
            *)
               # make sure file exists
               if ! test -e "${this_csr}" ;
               then
                  ferror "${scriptfile}: 1006. CSR file ${this_csr} is invalid or not found. Aborted." && exit 1006
               fi
               cat "${this_csr}" > "${CERTREQ_WORKDIR}/${this_filename}.csr"
               ;;
         esac
         ;;
      *)
         "${this_openssl_bin}" req ${this_openssl_config} -new -nodes \
            -out "${CERTREQ_WORKDIR}/${this_filename}.csr" \
            -keyout "${CERTREQ_WORKDIR}/${this_filename}.key" \
            -subj "${this_subject}"
         ;;
   esac

   CSR="$( cat "${CERTREQ_WORKDIR}/${this_filename}.csr" | tr -d '\n\r' )"
   DATA="Mode=newreq&CertRequest=${CSR}&C&TargetStoreFlags=0&SaveCert=yes"
   CSR="$( echo ${CSR} | sed -e 's/+/%2B/g' | tr -s ' ' '+' )"
   CERTATTRIB="CertificateTemplate:${CERTREQ_TEMPLATE}"

}

submit_csr() {
   # call: submit_csr "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CSR}" "${CERTATTRIB}" "${CERTREQ_ACTION}"
   # outputs: ${CERTLINK}
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"
   local this_cert="${4}"
   local this_cert_attrib="${5}"
   local this_action="${6}"

   case "${this_action}" in

      request)
         # request-only
         FULLPAGE="$( curl -k -u "${this_user_string}" --ntlm \
            "${this_ca}/certsrv/certfnsh.asp" \
            -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
            -H 'Accept-Encoding: gzip, deflate' \
            -H 'Accept-Language: en-US,en;q=0.5' \
            -H 'Connection: keep-alive' \
            -H "Host: ${this_ca_host}" \
            -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
            -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            --data "Mode=newreq&CertRequest=${this_cert}&CertAttrib=${this_cert_attrib}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" )"
         REQUESTID="$( echo "${FULLPAGE}" | grep "' nReqId" | awk -F'= ' '{print $2}' | sed -e 's/\r//g' )"
         CERTLINK="${CERTREQ_CA}/certsrv/certnew.cer?ReqID=${REQUESTID}"
         ;;

      *)
         # get cert
         FULLPAGE="$( curl -k -u "${this_user_string}" --ntlm \
            "${this_ca}/certsrv/certfnsh.asp" \
            -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
            -H 'Accept-Encoding: gzip, deflate' \
            -H 'Accept-Language: en-US,en;q=0.5' \
            -H 'Connection: keep-alive' \
            -H "Host: ${this_ca_host}" \
            -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
            -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            --data "Mode=newreq&CertRequest=${this_cert}&CertAttrib=${this_cert_attrib}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" )"
         OUTPUTLINK="$( echo "${FULLPAGE}" | grep -A 1 'function handleGetCert() {' | tail -n 1 | cut -d '"' -f 2 )"
         CERTLINK="${this_ca}/certsrv/${OUTPUTLINK}"
         ;;

   esac

   DISPOSITION="$( echo "${FULLPAGE}" | grep -oiE "The disposition message is.*" | grep -oiE "\".*" )"
   MESSAGE="$( echo "${FULLPAGE}" | grep -oiE "<title>401.*" | grep -oiE ">.*<" | tr -d '<>' )"
   MESSAGE="${MESSAGE:-${DISPOSITION}}" # use disposition if message is not available

}

fetch_signed_cert() {
   # call: fetch_signed_cert "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERTLINK}" "${CERTREQ_CNPARAM}" "${CERTREQ_ACTION}" "${CERTREQ_REQID}"
   # output:
   #    vars: ${curloutput}
   #    files: ${CERTREQ_WORKDIR}/${this_filename}.crt
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"
   local this_certlink="${4}"
   local this_filename="${5}"
   local this_action="${6}"
   local this_reqid="${7}"

   case "${this_action}" in
      fetch)
         if test -z "${this_reqid}" ;
         then
            ferror "${scriptfile}: 1006. For --fetch, please provide --reqid REQID. Aborted."
            exit 1006
         fi
         this_certlink="${CERTREQ_CA}/certsrv/certnew.cer?ReqID=${this_reqid}"
         ;;
      *)
         :
         ;;
   esac

   curl -k -u "${this_user_string}" --ntlm "${this_certlink}" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' > "${CERTREQ_WORKDIR}/${this_filename}.crt"
   curloutput=$?

}

get_number_of_current_ca_cert() {
   # call: get_number_of_current_ca_cert "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}"
   # outputs: ${CURRENTNUM}
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"

   RESPONSE="$( curl -s -k -u "${this_user_string}" --ntlm \
      "${this_ca}/certsrv/certcarc.asp" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' )"
   CURRENTNUM="$( echo "${RESPONSE}" | grep -oE 'nRenewals=[0-9]+'| tr -dc '[0-9]' )"

}

get_latest_ca_cert_chain() {
   # call: get_latest_ca_cert_chain "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CURRENTNUM}"
   # outputs:
   #    files: ${CHAIN_FILE}
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"
   local this_num="${4}"

   CURRENT_P7B="$( curl -s -k -u "${this_user_string}" --ntlm \
      "${this_ca}/certsrv/certnew.p7b?ReqID=CACert&Renewal=${this_num}" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' )"

   # CONVERT TO PEM
   echo "${CURRENT_P7B}" | "${CERTREQ_OPENSSL_BIN}" pkcs7 -print_certs -out "${CERTREQ_TEMPFILE}"

   # RENAME TO PROPER FILENAME
   # will read only the first cert, so get domain of issuer of it.
   CA_DOMAIN="$( "${CERTREQ_OPENSSL_BIN}" x509 -in "${CERTREQ_TEMPFILE}" -noout -issuer 2>/dev/null | sed -r -e 's/^.*CN=[A-Za-z0-9]+\.//;' )"
   CHAIN_FILE="chain-${CA_DOMAIN}.crt"
   mv -f "${CERTREQ_TEMPFILE}" "${CERTREQ_WORKDIR}/${CHAIN_FILE}" 1>/dev/null 2>&1

}

action_get_cert() {
   # call: action_get_cert "${CERTREQ_CNPARAM}" "${CERTREQ_SUBJECT}" "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERTREQ_ACTION}" "${CERTREQ_CSR}" "${CERTREQ_OPENSSL_BIN}" "${CERTREQ_config_string}"
   # outputs:
   #   vars: ${curloutput}
   #   files: ${CHAIN_FILE} ${CERTREQ_CNPARAM}.crt and .key and
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_cnparam="${1}"
   local this_subject="${2}"
   local this_user_string="${3}"
   local this_ca="${4}"
   local this_ca_host="${5}"
   local this_action="${6}"
   local this_csr="${7}"
   local this_openssl_bin="${8}"
   local this_openssl_config="${9}"

   # GENERATE PRIVATE KEY
   openssl_req "${this_cnparam}" "${this_subject}" "${this_action}" "${this_csr}" "${this_openssl_bin}" "${this_openssl_config}"
   debuglev 8 && {
      echo "CSR=${CSR}"
      echo "DATA=${DATA}"
      echo "CERTATTRIB=${CERTATTRIB}"
   }

   # SUBMIT CERTIFICATE SIGNING REQUEST
   submit_csr "${this_user_string}" "${this_ca}" "${this_ca_host}" "${CSR}" "${CERTATTRIB}" "${this_action}"
   debuglev 8 && {
      echo "FULLPAGE=${FULLPAGE}"
      echo "OUTPUTLINK=${OUTPUTLINK}"
      echo "CERTLINK=${CERTLINK}"
      echo "DISPOSITION=${DISPOSITION}"
      echo "MESSAGE=${MESSAGE}"
   }

   # FETCH SIGNED CERTIFICATE
   fetch_signed_cert "${this_user_string}" "${this_ca}" "${this_ca_host}" "${CERTLINK}" "${this_cnparam}" "${this_action}" "REQID-not-needed-for-this-action"
   debuglev 8 && {
      echo "curloutput=${curloutput}"
   }

   if ! fistruthy "${CERTREQ_SKIP_CACERTS}" ;
   then

      # GET NUMBER OF CURRENT CA CERT
      get_number_of_current_ca_cert "${this_user_string}" "${this_ca}" "${this_ca_host}"
      debuglev 8 && {
         echo "CURRENTNUM=${CURRENTNUM}"
      }

      # GET LATEST CA CERT CHAIN
      get_latest_ca_cert_chain "${this_user_string}" "${this_ca}" "${this_ca_host}" "${CURRENTNUM}"
      debuglev 8 && {
         echo "CHAIN_FILE=${CHAIN_FILE}"
      }

   fi

}

action_request() {
   # call: action_request "${CERTREQ_CNPARAM}" "${CERTREQ_SUBJECT}" "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERTREQ_ACTION}" "${CERTREQ_CSR}" "${CERTREQ_OPENSSL_BIN}" "${CERTREQ_openssl_config}"
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_cnparam="${1}"
   local this_subject="${2}"
   local this_user_string="${3}"
   local this_ca="${4}"
   local this_ca_host="${5}"
   local this_action="${6}"
   local this_csr="${7}"
   local this_openssl_bin="${8}"
   local this_openssl_config="${9}"

   # GENERATE PRIVATE KEY
   openssl_req "${this_cnparam}" "${this_subject}" "${this_action}" "${this_csr}" "${this_openssl_bin}" "${this_openssl_config}"
   debuglev 8 && {
      echo "CSR=${CSR}"
      echo "DATA=${DATA}"
      echo "CERTATTRIB=${CERTATTRIB}"
   }

   # SUBMIT CERTIFICATE SIGNING REQUEST
   submit_csr "${this_user_string}" "${this_ca}" "${this_ca_host}" "${CSR}" "${CERTATTRIB}" "${this_action}"
   debuglev 8 && {
      echo "FULLPAGE=${FULLPAGE}"
      echo "OUTPUTLINK=${OUTPUTLINK}"
      echo "CERTLINK=${CERTLINK}"
      echo "DISPOSITION=${DISPOSITION}"
      echo "MESSAGE=${MESSAGE}"
   }

}

action_fetch() {
   # call: action_fetch "${CERTREQ_CNPARAM}" "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERTREQ_ACTION}" "${CERTREQ_REQID}"
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_cnparam="${1}"
   local this_user_string="${2}"
   local this_ca="${3}"
   local this_ca_host="${4}"
   local this_action="${5}"
   local this_reqid="${6}"

   fetch_signed_cert "${this_user_string}" "${this_ca}" "${this_ca_host}" "WILL-BE-REPLACED" "${this_cnparam}" "${this_action}" "${this_reqid}"
   debuglev 8 && {
      echo "curloutput=${curloutput}"
   }

   if ! fistruthy "${CERTREQ_SKIP_CACERTS}" ;
   then

      # GET NUMBER OF CURRENT CA CERT
      get_number_of_current_ca_cert "${this_user_string}" "${this_ca}" "${this_ca_host}"
      debuglev 8 && {
         echo "CURRENTNUM=${CURRENTNUM}"
      }

      # GET LATEST CA CERT CHAIN
      get_latest_ca_cert_chain "${this_user_string}" "${this_ca}" "${this_ca_host}" "${CURRENTNUM}"
      debuglev 8 && {
         echo "CHAIN_FILE=${CHAIN_FILE}"
      }

   fi

}

action_list_templates() {
   # call: action_list_templates "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}"
   debuglev 9 && ferror "$FUNCNAME $@"

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"

   RESPONSE="$( curl -s -k -u "${this_user_string}" --ntlm \
      "${this_ca}/certsrv/certrqxt.asp" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqus.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' )"
   AVAILABLE_TEMPLATES="$( echo "${RESPONSE}" | grep -E -- "<Option" | grep -oE "Value=\".*\">" |awk -F';' -v 'a=0' 'BEGIN{OFS=","} {a=a+1; print a,$2,$14}' | sed -r -e 's/">\s*$//;' )"
   # goal: set a variable of the items, probably comma-delimited

}

file_section_has_value() {
   # call: file_section_has_value "${thisfile}" "${sectionregex}" "${nextsectionregex}" "${valueregex}"
   ___fshv_file="${1}"
   ___fshv_sectionregex="${2}"
   ___fshv_nextsectionregex="${3}"
   ___fshv_valueregex="${4}"
   test -n "$( sed -n -r -e "/${___fshv_sectionregex}/,/${___fshv_nextsectionregex}/p" "${___fshv_file}" 2>/dev/null | grep -q -r -e "${___fshv_valueregex}" )"
}

# DEFINE TRAPS

clean_certreq() {
   # use at end of entire script if you need to clean up tmpfiles
   #rm -f ${tmpfile} 1>/dev/null 2>&1
   if test -z "${CR_NC}";
   then
      nohup /bin/bash <<EOF 1>/dev/null 2>&1 &
sleep "${CERTREQ_CLEANUP_SEC:-300}" ; /bin/rm -r "${CERTREQ_WORKDIR:-NOTHINGTODELETE}" 2>/dev/null ;
EOF
   fi

}

CTRLC() {
   # use with: trap "CTRLC" 2
   # useful for controlling the ctrl+c keystroke
   :
}

CTRLZ() {
   # use with: trap "CTRLZ" 18
   # useful for controlling the ctrl+z keystroke
   :
}

parseFlag() {
   flag="$1"
   hasval=0
   case ${flag} in
      # INSERT FLAGS HERE
      "d" | "debug" | "DEBUG" | "dd" ) setdebug; ferror "debug level ${debug}";;
      "usage" | "help" | "h" ) usage; exit 1001;;
      "V" | "fcheck" | "version" ) ferror "${scriptfile} version ${certreqversion}"; exit 1001;;
      "u" | "user" | "username" ) getval; CERTREQ_USER="${tempval}";;
      "p" | "pass" | "password" ) getval; CERTREQ_PASS="${tempval}";;
      "w" | "work" | "workdir" ) getval; CERTREQ_WORKDIR="${tempval}";;
      "t" | "temp" | "template" ) getval; CERTREQ_TEMPLATE="${tempval}";;
      "cn" | "common-name" | "commonname" ) getval; CERTREQ_CNPARAM="${tempval}";;
      "ca" | "certauthority" | "cauthority" ) getval; CERTREQ_CAPARAM="${tempval}";;
      "c" | "conf" | "conffile" | "config" ) getval; conffile="${tempval}";;
      "nc" | "nocleanup" ) CR_NC=1;;
      "l" | "list" ) CERTREQ_ACTION="list";;
      "g" | "generate" ) CERTREQ_ACTION="generate";;
      "csr" ) CERTREQ_ACTION="${CERTREQ_ACTION:-generate}-csr"; getval; CERTREQ_CSR="${tempval}" ;;
      "fetch" | "fetch-only" ) CERTREQ_ACTION="fetch";;
      "request" | "request-only" ) CERTREQ_ACTION="request";;
      "no-ca" | "noca" ) CERTREQ_SKIP_CACERTS=1;;
      "req" | "reqid" | "req-id" | "request" | "requestid" | "request-id" ) getval; CERTREQ_REQID="${tempval}";;
      "openssl-bin" | "openssl" | "opensslbin" | "openssl-binary" | "opensslexec" | "openssl-exec" ) getval; CERTREQ_OPENSSL_BIN="${tempval}";;
      "openssl-conf" | "opensslconf" | "openssl_conf" ) getval; CERTREQ_OPENSSL_CONF="${tempval}";;
      "dnssans" | "dns-sans" | "dnssan" | "dns-san" ) getval; CERTREQ_DNSSANS="${tempval}";;
      "ipsans" | "ip-sans" | "ipsan" | "ip-san" ) getval; CERTREQ_IPSANS="${tempval}";;
   esac

   debuglev 10 && { test ${hasval} -eq 1 && ferror "flag: ${flag} = ${tempval}" || ferror "flag: ${flag}"; }
}

# DETERMINE LOCATION OF FRAMEWORK
while read flocation; do if test -f ${flocation} && test "$( sh ${flocation} --fcheck )" -ge 20170608; then frameworkscript="${flocation}"; break; fi; done <<EOFLOCATIONS
./framework.sh
${scriptdir}/framework.sh
/tmp/framework.sh
/usr/share/bgscripts/framework.sh
EOFLOCATIONS
test -z "${frameworkscript}" && echo "$0: framework not found. Aborted." 1>&2 && exit 1004

# INITIALIZE VARIABLES
# variables set in framework:
# today server thistty scriptdir scriptfile scripttrim
# is_cronjob stdin_piped stdout_piped stderr_piped sendsh sendopts
. ${frameworkscript} || echo "$0: framework did not run properly. Continuing..." 1>&2
infile1=
outfile1=
#logfile=${scriptdir}/${scripttrim}.${today}.out # defined farther down
define_if_new interestedparties "bgstack15@gmail.com"
# SIMPLECONF
define_if_new default_conffile "/tmp/certreq.conf"
define_if_new defuser_conffile ~/.config/certreq/certreq.conf

# REACT TO OPERATING SYSTEM TYPE
case $( uname -s ) in
   Linux) [ ];;
   *) echo "${scriptfile}: 3. Indeterminate OS: $( uname -s )" 1>&2 && exit 1003;;
esac

## REACT TO ROOT STATUS
#case ${is_root} in
#   1) # proper root
#      [ ] ;;
#   sudo) # sudo to root
#      [ ] ;;
#   "") # not root at all
#      #ferror "${scriptfile}: 5. Please run as root or sudo. Aborted."
#      #exit 1005
#      [ ]
#      ;;
#esac

# SET CUSTOM SCRIPT AND VALUES
#setval 1 sendsh sendopts<<EOFSENDSH      # if $1="1" then setvalout="critical-fail" on failure
#/usr/share/bgscripts/send.sh -hs     #                setvalout maybe be "fail" otherwise
#/usr/local/bin/send.sh -hs               # on success, setvalout="valid-sendsh"
#/usr/bin/mail -s
#EOFSENDSH
#test "${setvalout}" = "critical-fail" && ferror "${scriptfile}: 4. mailer not found. Aborted." && exit 1004

# VALIDATE PARAMETERS
# objects before the dash are options, which get filled with the optvals
# to debug flags, use option DEBUG. Variables set in framework: fallopts
validateparams - "$@"

# CONFIRM TOTAL NUMBER OF FLAGLESSVALS IS CORRECT
#if test ${thiscount} -lt 2;
#then
#   ferror "${scriptfile}: 2. Fewer than 2 flaglessvals. Aborted."
#   exit 1002
#fi

# LOAD CONFIG FROM SIMPLECONF
# This section follows a simple hierarchy of precedence, with first being used:
#    1. parameters and flags
#    2. environment
#    3. config file
#    4. default user config: ~/.config/script/script.conf
#    5. default config: /etc/script/script.conf
if test -f "${conffile}";
then
   get_conf "${conffile}"
else
   if test "${conffile}" = "${default_conffile}" || test "${conffile}" = "${defuser_conffile}"; then :; else test -n "${conffile}" && ferror "${scriptfile}: Ignoring conf file which is not found: ${conffile}."; fi
fi
test -f "${defuser_conffile}" && get_conf "${defuser_conffile}"
test -f "${default_conffile}" && get_conf "${default_conffile}"

# CONFIGURE VARIABLES AFTER PARAMETERS
define_if_new CERTREQ_USER "ANONYMOUS"
define_if_new CERTREQ_PASS "NOPASSWORD"
test -z "${CERTREQ_WORKDIR}" && CERTREQ_WORKDIR="$( mktemp -d )"
define_if_new CERTREQ_TEMPLATE "ConfigMgrLinuxClientCertificate"
define_if_new CERTREQ_CNLONG "$( hostname -f )"
define_if_new CERTREQ_CNSHORT "$( echo "${CERTREQ_CNLONG%%.*}" )"
define_if_new CERTREQ_CLEANUP_SEC 300
logfile="$( TMPDIR="${CERTREQ_WORKDIR}" mktemp -t tmp.XXXXXXXXXX )"
CERTREQ_TEMPFILE="$( TMPDIR="${CERTREQ_WORKDIR}" mktemp -t tmp.XXXXXXXXXX )"
define_if_new CERTREQ_ACTION "generate"
define_if_new CERTREQ_OPENSSL_BIN "openssl"
# no default CERTREQ_OPENSSL_CONF. Just use system default.
# no default CERTREQ_DNSSANS, which is pipe-delimited.
# no default CERTREQ_IPSANS, which is pipe-delimited.

# calculate the subject
if test -n "${CERTREQ_CNPARAM}";
then
   # ensure good CN format.
   CERTREQ_CNPARAM="$( echo "${CERTREQ_CNPARAM}" | sed -r -e 's/^CN=//i;' )"
   case "${CERTREQ_CNPARAM}" in
      "${CERTREQ_CNLONG}" | "${CERTREQ_CNSHORT}" ) : ;;
      *) ferror "Using custom CN \"${CERTREQ_CNPARAM}\"" ;;
   esac
else
   CERTREQ_CNPARAM="${CERTREQ_CNLONG}"
fi
CERTREQ_SUBJECT="$( echo ${CERTREQ_SUBJECT} | sed -r -e "s/CERTREQ_CNPARAM/${CERTREQ_CNPARAM}/g;" )"
define_if_new CERTREQ_SUBJECT "/DC=com/DC=example/DC=ad/CN=${CERTREQ_CNSHORT}/CN=${CERTREQ_CNPARAM}"

# calculate the MSCA
if test -n "${CERTREQ_CAPARAM}";
then
   # trim down to just the hostname
   CERTREQ_CAPARAM="$( echo "${CERTREQ_CAPARAM}" | sed -r -e 's/https?:\/\///g' -e 's/(\.[a-z]{2,3})\/$/\1/;' )"
   CERTREQ_CA="http://${CERTREQ_CAPARAM}"
fi
define_if_new CERTREQ_CA "http://ca2.ad.example.com"
# generate cahost
CERTREQ_CAHOST="$( echo "${CERTREQ_CA}" | sed -r -e 's/https?:\/\///g' -e 's/(\.[a-z]{2,3})\/$/\1/;' )"

# verify openssl_conf dependency
if test -n "${CERTREQ_OPENSSL_CONF}" ;
then
   if ! test -r "${CERTREQ_OPENSSL_CONF}" ;
   then
      ferror "${scriptfile}: 1004. CERTREQ_OPENSSL_CONF file ${CERTREQ_OPENSSL_CONF} is invalid or not found. Aborted." && exit 1004
   fi
fi

## REACT TO BEING A CRONJOB
#if test ${is_cronjob} -eq 1;
#then
#   [ ]
#else
#   [ ]
#fi

# SET TRAPS
#trap "CTRLC" 2
#trap "CTRLZ" 18
trap "clean_certreq" 0

# PREPARE CUSTOM CONF FILE WITH ANY SUBJECTALTNAME ENTRIES
if test -n "${CERTREQ_DNSSANS}${CERTREQ_IPSANS}" ;
then

   # initialize new conf file
   CERTREQ_openssl_conf_new="$( TMPDIR="${CERTREQ_WORKDIR}" mktemp -t openssl.cnf.XXXXXXXXXX )"

   # select conf file
   if test -z "${CERTREQ_OPENSSL_CONF}" ;
   then
      # need to calculate the default conf file
      CERTREQ_first_found="$( find /etc/ssl/openssl.cnf /usr/local/ssl/openssl.cnf 2>/dev/null | head -n1 )"
      if ! test -r "${CERTREQ_first_found}" ;
      then
         ferror "${scriptfile}: 1004. Cannot determine default openssl.cnf for inserting SANs. Aborted." && exit 1004
      else
         CERTREQ_OPENSSL_CONF="${CERTREQ_first_found}" && unset CERTREQ_first_found
      fi
   fi

   # copy in contents
   /bin/cp -p "${CERTREQ_OPENSSL_CONF}" "${CERTREQ_openssl_conf_new}"
   CERTREQ_OPENSSL_CONF="${CERTREQ_openssl_conf_new}" && unset CERTREQ_openssl_conf_new

   # make modifications, add v3_req
   #if test -z "$( sed -n -r -e '/^\s*\[ req \]/,/^\s*\[/p' "${CERTREQ_OPENSSL_CONF}" 2>/dev/null | grep -r -e '^\s*req_extensions' )" ;
   if ! file_section_has_value "${CERTREQ_OPENSSL_CONF}" "^\s*\[ req \]" "^\s*\[" "^\s*req_extensions" ;
   then
      # need to add req_extensions = v3_req to [ req ]
      # get line number of [ req ]
      CERTREQ_line_num="$( awk '/^\s*\[ req \]/{print FNR}' "${CERTREQ_OPENSSL_CONF}" 2>/dev/null )"
      if test -z "${CERTREQ_line_num}" ;
      then
         # no line containing
         echo "[ req ]" >> "${CERTREQ_OPENSSL_CONF}"
         CERTREQ_line_num="$( wc -l < "${CERTREQ_OPENSSL_CONF}" )"
      fi
      sed -i -r -e "${CERTREQ_line_num}areq_extensions = v3_req" "${CERTREQ_OPENSSL_CONF}"
   fi

   # make modifications, add SAN to [ v3_req ]
   #if test -z "$( sed -n -r -e '/^\s*\[ v3_req \]/,/^\s*\[/p' "${CERTREQ_OPENSSL_CONF}" 2>/dev/null | grep
   if ! file_section_has_value "${CERTREQ_OPENSSL_CONF}" "^\s*\[ v3_req \]" "^\s*\[" "^\s*subjectAltName" ;
   then
      # need to add it
      CERTREQ_line_num="$( awk '/^\s*\[ v3_req \]/{print FNR}' "${CERTREQ_OPENSSL_CONF}" 2>/dev/null )"
      if test -z "${CERTREQ_line_num}" ;
      then
         # need to add the section too
         echo "[ v3_req ]" >> "${CERTREQ_OPENSSL_CONF}"
         CERTREQ_line_num="$( wc -l < "${CERTREQ_OPENSSL_CONF}" )"
      fi
      sed -i -r -e "${CERTREQ_line_num}asubjectAltName = @alt_names" "${CERTREQ_OPENSSL_CONF}"
   fi

   # make modifications, add subject alt names section
   # start by preparing the exact string to make
   CERTREQ_san_lines="$( test -n "${CERTREQ_DNSSANS}" && echo "${CERTREQ_DNSSANS}" | tr '|' '\n' | awk 'BEGIN{a=0} {a=a+1 ; print "DNS."a" = "$0 ;}' ; test -n "${CERTREQ_IPSANS}" && echo "${CERTREQ_IPSANS}" | tr '|' '\n' | awk 'BEGIN{a=0} {a=a+1 ; print "IP."a" = "$0 ;}')"
   # add to file
   if ! file_section_has_value "${CERTREQ_OPENSSL_CONF}" "^\s*\[alt_names\]" "^\s*\[" "=" ;
   then
      # need to add the values
      CERTREQ_line_num="$( awk '/^\s*\[alt_names\]/{print FNR}' "${CERTREQ_OPENSSL_CONF}" 2>/dev/null )"
      if test -z "${CERTREQ_line_num}" ;
      then
         # need to add the section too
         echo "[alt_names]" >> "${CERTREQ_OPENSSL_CONF}"
         CERTREQ_line_num="$( wc -l < "${CERTREQ_OPENSSL_CONF}" )"
      fi
      echo "${CERTREQ_san_lines}" | while read line ; do sed -i -r -e "${CERTREQ_line_num}a${line}" "${CERTREQ_OPENSSL_CONF}" ; CERTREQ_line_num=$(( CERTREQ_line_num + 1 )) ; done
   fi

   # clean up
   unset CERTREQ_line_num
fi

if test -n "${CERTREQ_OPENSSL_CONF}" ;
then
   CERTREQ_openssl_config="-config ${CERTREQ_OPENSSL_CONF}"
fi

# DEBUG SIMPLECONF
debuglev 5 && {
   ferror "Using values"
   # used values: EX_(OPT1|OPT2|VERBOSE)
   set | grep -iE "^CERTREQ_" | {
      if fistruthy "${NO_MASK}" ;
      then
         cat
      else
         sed -r -e 's/(CERTREQ_PASS=).*$/\1**********************/;'
      fi
   } 1>&2
}

# MAIN LOOP
{

   case "${CERTREQ_ACTION}" in

      list)
         action_list_templates "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}"
         ;;

      request)
         # alias of "request-only"
         action_request "${CERTREQ_CNPARAM}" "${CERTREQ_SUBJECT}" "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERTREQ_ACTION}" "${CERTREQ_CSR}" "${CERTREQ_OPENSSL_BIN}" "${CERTREQ_openssl_config}"
         ;;

      fetch)
         # alias of "fetch-only"
         action_fetch "${CERTREQ_CNPARAM}" "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERTREQ_ACTION}" "${CERTREQ_REQID}"
         ;;

      *)
         # default action="generate"
         # also catches "generate-csr"
         action_get_cert "${CERTREQ_CNPARAM}" "${CERTREQ_SUBJECT}" "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERTREQ_ACTION}" "${CERTREQ_CSR}" "${CERTREQ_OPENSSL_BIN}" "${CERTREQ_openssl_config}"
         ;;

   esac

   # CHECK EVERYTHING
   failed=0 # start out with everything worked
   openssloutput="$( "${CERTREQ_OPENSSL_BIN}" x509 -in "${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt" -noout -subject -issuer -startdate -enddate 2>/dev/null )"

   # 1 interaction with website failed: invalid login credentials or curl returned non-zero value
   if echo "${MESSAGE}" | grep -qiE 'unauthorized'  || test ${curloutput} -ne 0 ;
   then
      failed=$(( failed + 1 ))
   fi

   # 2 cert request denied
   if echo "${MESSAGE}" | grep -qiE 'policy' ;
   then
      failed=$(( failed + 2 ))
   fi

   # 4 invalid cert file: incomplete cert file, or no issuer
   if { ! grep -qE -- '--END CERTIFICATE--' "${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt" ; } || { ! echo "${openssloutput}" | grep -qE "issuer.*" ; } ;
   then
      failed=$(( failed + 4 ))
   fi

} 1> ${logfile} 2>&1

case "${CERTREQ_ACTION}" in

   list)
      # echo the variable from action_list_templates
      echo "${AVAILABLE_TEMPLATES}"
      ;;

   request)
      echo "workdir: ${CERTREQ_WORKDIR}"
      echo "logfile: ${logfile}"
      test -n "${CERTREQ_OPENSSL_CONF}" && echo "openssl_conf: ${CERTREQ_OPENSSL_CONF}"
      echo "csr: ${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.csr"
      echo "key: ${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.key"
      echo "reqid: ${REQUESTID}"
      echo "message: ${MESSAGE}"
      echo "rc: ${failed}"
      ;;

   fetch)
      echo "workdir: ${CERTREQ_WORKDIR}"
      echo "logfile: ${logfile}"
      echo "certificate: ${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt"
      ! fistruthy "${CERTREQ_SKIP_CACERTS}" && echo "chain: ${CERTREQ_WORKDIR}/${CHAIN_FILE}"
      echo "rc: ${failed}"
      ;;

   generate*)
      # for generate and generate-csr and everything else really
      echo "workdir: ${CERTREQ_WORKDIR}"
      echo "logfile: ${logfile}"
      test -n "${CERTREQ_OPENSSL_CONF}" && echo "openssl_conf: ${CERTREQ_OPENSSL_CONF}"
      echo "csr: ${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.csr"
      echo "certificate: ${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt"
      echo "key: ${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.key"
      ! fistruthy "${CERTREQ_SKIP_CACERTS}" && echo "chain: ${CERTREQ_WORKDIR}/${CHAIN_FILE}"
      echo "message: ${MESSAGE}"
      echo "rc: ${failed}"
      ;;

esac

clean_certreq

exit_code() { return "${1:-0}" ; }
exit_code "${failed:-0}"

# EMAIL LOGFILE
#${sendsh} ${sendopts} "${server} ${scriptfile} out" ${logfile} ${interestedparties}
