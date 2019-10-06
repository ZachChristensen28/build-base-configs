#!/bin/bash

# Splunk Default Variables
MGMT_PORT=8089
IDX_LISTEN_PORT=9997

# all_indexes
build_all_indexes () {
  idx_base="${PROJ_APP_PATH}_${1}/local"
  cat <<EOF > "${idx_base}/indexes.conf"
# Parameters commonly leveraged here:
# maxTotalDataSizeMB - sets the maximum size of the index data, in MBytes,
#   over all stages (hot, warm, cold). This is the *indexed* volume (actual
#   disk space used) not the license volume. This is separate from volume-
#   based retention and the lower of this and volumes will take effect.
#   NOTE: THIS DEFAULTS TO 500GB - BE SURE TO RAISE FOR LARGE ENVIRONMENTS!
#
# maxDataSize - this constrains how large a *hot* bucket can grow; it is an
#   upper bound. Buckets may be smaller than this (and indeed, larger, if
#   the data source grows very rapidly--Splunk checks for the need to rotate
#   every 60 seconds).
#   "auto" means 750MB
#   "auto_high_volume" means 10GB on 64-bit systems, and 1GB on 32-bit.
#   Otherwise, the number is given in MB
#   (Default: auto)
#
# maxHotBuckets - this defines the maximum number of simultaneously open hot
#   buckets (actively being written to). For indexes that receive a lot of
#   data, this should be 10, other indexes can safely keep the default
#   value. (Default: 3)
#
# homePath - sets the directory containing hot and warm buckets. If it
#   begins with a string like "volume:<name>", then volume-based retention is
#   used. [required for new index]
#
# coldPath - sets the directory containing cold buckets. Like homePath, if
#   it begins with a string like "volume:<name>", then volume-based retention
#   will be used. The homePath and coldPath can use the same volume, but
#   but should have separate subpaths beneath it. [required for new index]
#
# thawedPath - sets the directory for data recovered from archived buckets
#   (if saved, see coldToFrozenDir and coldToFrozenScript in the docs). It
#   *cannot* reference a volume: specification. This parameter is required,
#   even if thawed data is never used. [required for new index]
#
# frozenTimePeriodInSecs - sets the maximum age, in seconds, of data. Once
#   *all* of the events in an index bucket are older than this age, the
#   bucket will be frozen (default action: delete). The important thing
#   here is that the age of a bucket is defined by the *newest* event in
#   the bucket, and the *event time*, not the time at which the event
#   was indexed.
# TSIDX MINIFICATION (version 6.4 or higher)
#   Reduce the size of the tsidx files (the "index") within each bucket to
#   a tiny one for space savings. This has a *notable* impact on search,
#   particularly those which are looking for rare or sparse terms, so it
#   should not be undertaken lightly. First enable the feature with the
#   first option shown below, then set the age at which buckets become
#   eligible.
# enableTsidxReduction = true / (false) - Enable the function to reduce the
#   size of tsidx files within an index. Buckets older than the time period
#   shown below.
# timePeriodInSecBeforeTsidxReduction - sets the minimum age for buckets
#   before they are eligible for their tsidx files to be minified. The
#   default value is 7 days (604800 seconds).
# Seconds Conversion Cheat Sheet
#    86400 = 1 day
#   604800 = 1 week
#  2592000 = 1 month
# 31536000 = 1 year

[default]
lastChanceIndex = main

# Default for each index. Can be overridden per index based upon the volume of data received by that index.
# 300GB
# homePath.maxDataSizeMB = 300000
# 200GB
# coldPath.maxDataSizeMB = 200000

# VOLUME SETTINGS
# In this example, the volume spec is not defined here, it lives within
# the org_(indexer|search)_volume_indexes app, see those apps for more
# detail.

# One Volume for Hot and Cold
# [volume:primary]
# path = /opt/splunk/var/lib/splunk
# 500GB
# maxVolumeDataSizeMB = 500000

# Two volumes for a "tiered storage" solution--fast and slow disk.
# [volume:home]
# path = /path/to/fast/disk
# maxVolumeDataSizeMB = 256000
#
# Longer term storage on slower disk.
# [volume:cold]
# path = /path/to/slower/disk
# 5TB with some headroom leftover (data summaries, etc)
# maxVolumeDataSizeMB = 4600000

# SPLUNK INDEXES
# Note, many of these use historical directory names which don't match the
# name of the index. A common mistake is to automatically generate a new
# indexes.conf from the existing names, thereby "losing" (hiding from Splunk)
# the existing data.
[main]
homePath   = volume:primary/defaultdb/db
coldPath   = volume:primary/defaultdb/colddb
thawedPath = \$SPLUNK_DB/defaultdb/thaweddb

[history]
homePath   = volume:primary/historydb/db
coldPath   = volume:primary/historydb/colddb
thawedPath = \$SPLUNK_DB/historydb/thaweddb

[summary]
homePath   = volume:primary/summarydb/db
coldPath   = volume:primary/summarydb/colddb
thawedPath = \$SPLUNK_DB/summarydb/thaweddb

[_internal]
homePath   = volume:primary/_internaldb/db
coldPath   = volume:primary/_internaldb/colddb
thawedPath = \$SPLUNK_DB/_internaldb/thaweddb

# For version 6.1 and higher
[_introspection]
homePath   = volume:primary/_introspection/db
coldPath   = volume:primary/_introspection/colddb
thawedPath = \$SPLUNK_DB/_introspection/thaweddb

# For version 6.5 and higher
[_telemetry]
homePath   = volume:primary/_telemetry/db
coldPath   = volume:primary/_telemetry/colddb
thawedPath = \$SPLUNK_DB/_telemetry/thaweddb

[_audit]
homePath   = volume:primary/audit/db
coldPath   = volume:primary/audit/colddb
thawedPath = \$SPLUNK_DB/audit/thaweddb

[_thefishbucket]
homePath   = volume:primary/fishbucket/db
coldPath   = volume:primary/fishbucket/colddb
thawedPath = \$SPLUNK_DB/fishbucket/thaweddb

# No longer supported in Splunk 6.3
# [_blocksignature]
# homePath   = volume:primary/blockSignature/db
# coldPath   = volume:primary/blockSignature/colddb
# thawedPath = \$SPLUNK_DB/blockSignature/thaweddb

# SPLUNKBASE APP INDEXES

# CUSTOMER INDEXES
# TEMPLATE
#[my_index]
#homePath = volume:primary/\$_index_name/db
#coldPath = volume:primary/\$_index_name/colddb
#thawedPath = \$SPLUNK_DB/\$_index_name/thaweddb
#maxTotalDataSizeMB = 5242880
#maxDataSize = auto_high_volume
#maxWarmDBCount = 4294967295
#maxHotBuckets = 10
# 2.5TB for Hot/Warm & 2.5TB for cold
#homePath.maxDataSizeMB = 2621440
#coldPath.maxDataSizeMB = 2621440
# 30 days in seconds
#frozenTimePeriodInSecs = 2592000
EOF
}

# all_indexer_base
build_all_indexer_base () {
  idx_base="${PROJ_APP_PATH}_${1}/local"
  cat <<EOF > "${idx_base}/indexes.conf"
# Enables various performance and space-saving improvements for tsidx files.
# Should always be set to the highest value available for all indexes.
[default]
tsidxWritingLevel = 3
EOF
  cat <<EOF > "${idx_base}/inputs.conf"
# BASE SETTINGS
[splunktcp://${IDX_LISTEN_PORT}]
# [splunktcp-ssl://9996]

# SSL SETTINGS
# [SSL]
# rootCA = $SPLUNK_HOME/etc/auth/cacert.pem
# serverCert = $SPLUNK_HOME/etc/auth/server.pem
# sslPassword = password
# requireClientCert = false
# If using compressed = true, it must be set on the forwarder outputs as well.
# compressed = true
EOF

  cat <<EOF > "${idx_base}/web.conf"
# In larger environments, where there are more than, say, three indexers,
# it's common to disable the Splunk UI. This helps avoid configuration issues
# caused by logging in to the UI to do something directly via the manager,
# as well as saving some system resources.

# [settings]
# startwebserver = 0
EOF
}

build_indexer_volume_indexes () {
  idx_base="${PROJ_APP_PATH}_${1}/local"
  cat <<EOF > "${idx_base}/indexes.conf"
# VOLUME SETTINGS
# In this example, the volume spec here is set to the indexer-specific
# path for data storage. It satisfies the "volume:primary" tag used in
# the indexes.conf which is shared between SH and indexers.
# See also: org_all_indexes

# One Volume for Hot and Cold
[volume:primary]
#path = /opt/splunk/var/lib/splunk
path = /path/to/index/storage/partition
# Note: The *only* reason to use a volume is to set a cumulative size-based
# limit across several indexes stored on the same partition. There are *not*
# time-based volume limits.
# ~5 TB
maxVolumeDataSizeMB = 5000000

# This setting changes the storage location for _splunk_summaries,
# which should be utilized if you want to use the same partition
# as specified for volume settings. Otherwise defaults to \$SPLUNK_DB.
#
# The size setting of the volume shown below would place a limit on the
# total size of data model acceleration (DMA) data. Doing so should be
# carefully considered as it may have a negative impact on appilcations
# like Enterprise Security.
#
# [volume:_splunk_summaries]
# path = /path/to/index/storage/partition
# ~ 100GB
# maxVolumeDataSizeMB = 100000
EOF
}

build_all_deployment_client() {
  base="${PROJ_APP_PATH}_${1}/local"
  cat <<EOF > ${base}/deploymentclient.conf
[deployment-client]
# Set the phoneHome at the end of the PS engagement
# 10 minutes
# phoneHomeIntervalInSecs = 600

[target-broker:deploymentServer]
# Change the targetUri
targetUri = ${DS_IP}:${MGMT_PORT}
EOF
}

build_sh_cluster_deployer_base() {
  base="${PROJ_APP_PATH}_${1}/local"
  base_dir="${PROJ_DIR}/${PROJ_PREFIX}_${1}"
  newBase="$PROJ_DIR/${PROJ_PREFIX}_search_head_cluster"
  peer_arr=($SHC_PEERS)
  cat <<EOF > ${base}/server.conf
[shclustering]
pass4SymmKey = mysecret
# the cluster label must be set the same on every memeber if set on one.
#shcluster_label = $SHC_LABEL
EOF

  mkdir "$newBase" || build_warn "Cannot create directory at \"${newBase}\"!"
  mv "$base_dir" "$newBase"

  for peer in "${peer_arr[@]}"; do
    peers+="https://${peer}:${MGMT_PORT},"
  done
  cat <<EOF > "${newBase}/bootstrap_captain.txt"
splunk bootstrap shcluster-captain -servers_list '${peers%,}'
EOF

  for peer in "${peer_arr[@]}"; do
    cat <<EOF >> "${newBase}/init_sh_peer.txt"
splunk init shcluster-config -mgmt_uri https://${peer}:${MGMT_PORT} -replication_port $SHC_REP_PORT -replication_factor $SHC_REP_FACTOR -conf_deploy_fetch_url https://${SHC_DR_IP}:${MGMT_PORT} -secret '<NEW PASSWOR>' -shcluster_label $SHC_LABEL

EOF
  done
}

build_all_search_base() {
  base="${PROJ_APP_PATH}_${1}/local"
  cat <<EOF > ${base}/authentication.conf
# See also:
# http://docs.splunk.com/Documentation/Splunk/latest/Admin/Authenticationconf

[authentication]
authType = LDAP
authSettings = org_ldap_auth

[org_ldap_auth]
# Dictates whether or not SSL is used for LDAP settings.
# This can commonly be guessed by the TCP port used for LDAP communications:
# 389 = no SSL
# 636 = SSL
SSLEnabled = 1
# This is the DN of the "user" account with which to bind to the directory.
# It is commonly supplied by the LDAP admins. For notational shorthand,
# there are abbreviations in the DN (Distinguished Name) of this user, here
# are a few:
# ou = Organizational Unit (e.g. department)
# o = Organization
# dc = Domain Component (e.g. "com" in "company.com")
# uid = User ID
# cn = Common Name
bindDN = cn=splunk_ldap,ou=accounts,ou=groups,dc=company,dc=com
# Where in the tree should Splunk start looking for groups? Child objects below
# this will be searched, so this should be the "root" or "greatest common
# component" of the LDAP path to the collection of groups to be mapped to
# Splunk. If there are multiple paths (as large organizations are likely
# to have), then multiple paths, separated by semicolons, can be used.
groupBaseDN = ou=groups,dc=company,dc=com
# A group uses what attribute to declare a user as a member...?
groupMemberAttribute = member
# What attribute of the group is used to identify it later for role mappings?
groupNameAttribute = cn
# The hostname of the LDAP server.
host = ldap.company.com
port = 636
# This is an attribute on a user to find their "real name" for the human-
# readable display in the LDAP auth settings page.
realNameAttribute = cn
# Where in the LDAP tree are users defined?
userBaseDN = ou=accounts,ou=groups,dc=company,dc=com
# The value of this attribute is searched for what the user types in as
# their user name for authentication purposes.
userNameAttribute = uid

# This maps groups to roles in Splunk. See also authorize.conf.
# In order to log in, a user must
#   exist in the directory
#   provide the correct password
#   be a member of a group that has been mapped to a Splunk role
# This is one way to manage users by sharing the same LDAP configuration
# across multiple search heads, but limiting the roleMap entries only to
# the LDAP groups which are permitted to log in.
# If multiple LDAP groups exist on the RHS of the mapping, they should
# be separated by semicolons. NOTE: Attempting to map multiple groups to
# the same role by providing multiple key=value pairs with the same Splunk
# role listed as the key will NOT work.
[roleMap_org_ldap_auth]
# Remember this is contained somewhere under groupBaseDN
admin = Splunk_Admins
user = Splunk_Users
network = Network_Admins
EOF

  cat <<EOF > ${base}/authorize.conf
# If the customer has a desire for custom roles to land at a default app,
# this would be done in the user-prefs.conf configuration file in
# $SPLUNK_HOME/etc/apps/user-prefs/local. The syntax would be:
# (global default)
# [general_default]
# default_namespace = <directory_name_of_app>
# E.g.
# default_namespace = splunk_app_windows_infrastructure
#
# (role default)
# [role_<role>]
# default_namespace = search

[role_org_custom]
# These two limits are across *all members of the role*, 0 = unlimited
cumulativeRTSrchJobsQuota = 0
cumulativeSrchJobsQuota = 0
# Maximum number of historical (non-real-time) searches for the user
srchJobsQuota = 3
importRoles = user
# These users are restricted to these two indexes
srchIndexesAllowed = main;customer
# If the user does not provide "index=" in their search string, look here:
srchIndexesDefault = customer
# These users can only see back one week
srchTimeWin = 7days

[role_org_network]
cumulativeRTSrchJobsQuota = 0
cumulativeSrchJobsQuota = 0
# Importing the "power" role gives real time search capability.
importRoles = power;user
# Number of concurrent real-time searches (see also the real time search
# capability--this role, drawing from stock 'user' has no RT search capability)
rtJobsQuota = 1
# These users can search more concurrently, maybe because of a busy dashboard.
srchJobsQuota = 5
# These users are allowed to search any index that is not an internal one
# (such as _audit or _internal)
srchIndexesAllowed = *
srchIndexesDefault = main;network;firewall
srchTimeWin = 30days

[role_org_admin]
cumulativeRTSrchJobsQuota = 0
cumulativeSrchJobsQuota = 0
# This is like inheriting from the 'admin' role
admin_all_objects = enabled
# These users can search anything, but will probably need to use "index="
# in their search to find what they're looking for.
srchIndexesAllowed = *;_*
srchIndexesDefault = main
srchTimeWin = 0
EOF

  cat <<EOF > ${base}/limits.conf
# Use these settings to increase the workload the search head can perform.

#[scheduler]
#max_searches_perc = 75
#auto_summary_perc = 100
EOF

  cat <<EOF > ${base}/outputs.conf
[indexAndForward]
index = false

[tcpout]
forwardedindex.filter.disable = true
indexAndForward = false
EOF

  cat <<EOF > ${base}/web.conf
# For customers who want Splunk to run HTTPS
[settings]
enableSplunkWebSSL = true
# And if they want to use their own certificates
# This is relative to $SPLUNK_HOME if it is not an absolute path
# privKeyPath = etc/auth/splunkweb/privkey.pem
# This is also relative to $SPLUNK_HOME
# serverCert = etc/auth/splunkweb/cert.pem

# To disable the "A new version of Splunk is available!" message on the
# login page
# updateCheckerBaseURL = 0
EOF
}

build_search_volume_indexes() {
  base="${PROJ_APP_PATH}_${1}/local"
  cat <<EOF > ${base}/indexes.conf
# SEARCH HEAD VOLUME SETTINGS
# In this example, the volume spec is only here to satisfy the
# "volume:<name>" tag in the indexes.conf. Indexes are shared between
# indexers and search heads, even though SH are not indexing any data
# locally. The SH uses this index list to validate the target of summary
# indexed data in the UI, or to provide typeahead for users trying to
# search for "index=...".
# In this instance, we do *not* use a maxVolumeDataSizeMB, because it
# doesn't matter.
# See also: org_full_indexes, org_indexer_volume_indexes

# One Volume for Hot and Cold
[volume:primary]
path = /opt/splunk/var/lib/splunk

[volume:secondary]
path = /opt/splunk/var/lib/splunk
EOF
}

build_all_forwarder_outputs() {
  base="${PROJ_APP_PATH}_${1}/local"
  cat <<EOF > ${base}/limits.conf
# By default a universal or light forwarder is limited to 256kB/s
# Either set a different limit in kB/s, or set the value to zero to
# have no limit.
# Note that a full speed UF can overwhelm a single indexer.

# [thruput]
# maxKBps = 0
EOF

  cat <<EOF > ${base}/outputs.conf
# BASE SETTINGS

[tcpout]
defaultGroup = primary_indexers

# When indexing a large continuous file that grows very large, a universal
# or light forwarder may become "stuck" on one indexer, trying to reach
# EOF before being able to switch to another indexer. The symptoms of this
# are congestion on *one* indexer in the pool while others seem idle, and
# possibly uneven loading of the disk usage for the target index.
# In this instance, forceTimebasedAutoLB can help!
# ** Do not enable if you have events > 64kB **
forceTimebasedAutoLB = true

# Load Balance by Volume
# autoLBVolume = <integer>

# Correct an issue with the default outputs.conf for the Universal Forwarder
# or the SplunkLightForwarder app; these don't forward _internal events.
forwardedindex.2.whitelist = (_audit|_introspection|_internal)

[tcpout:primary_indexers]
server = server_one:9997, server_two:9997

# If you do not have two (or more) indexers, you must use the single stanza
# configuration, which looks like this:
#[tcpout-server://<ipaddress_or_servername>:<port>]
# <attribute1> = <val1>



# If setting compressed=true, this must also be set on the indexer.
# compressed = true

# INDEXER DISCOVERY (ASK THE CLUSTER MASTER WHERE THE INDEXERS ARE)

# This particular setting identifies the tag to use for talking to the
# specific cluster master, like the "primary_indexers" group tag here.
# indexerDiscovery = clustered_indexers

# It's OK to have a tcpout group like the one above *with* a server list;
# these will act as a seed until communication with the master can be
# established, so it's a good idea to have at least a couple of indexers
# listed in the tcpout group above.

# [indexer_discovery:clustered_indexers]
# pass4SymmKey = <MUST_MATCH_MASTER>
# This must include protocol and port like the example below.
# master_uri = https://master.example.com:8089

# SSL SETTINGS

# sslCertPath = $SPLUNK_HOME/etc/auth/server.pem
# sslRootCAPath = $SPLUNK_HOME/etc/auth/ca.pem
# sslPassword = password
# sslVerifyServerCert = true

# COMMON NAME CHECKING - NEED ONE STANZA PER INDEXER
# The same certificate can be used across all of them, but the configuration
# here requires these settings to be per-indexer, so the same block of
# configuration would have to be repeated for each.
# [tcpout-server://10.1.12.112:9997]
# sslCertPath = $SPLUNK_HOME/etc/certs/myServerCertificate.pem
# sslRootCAPath = $SPLUNK_HOME/etc/certs/myCAPublicCertificate.pem
# sslPassword = server_privkey_password
# sslVerifyServerCert = true
# sslCommonNameToCheck = servername
# sslAltNameToCheck = servername
EOF
}

build_app_base() {
  app_path="${PROJ_DIR}/${PROJ_PREFIX}_$1"
  mkdir -p ${app_path}/{local,metadata} || build_warn "Cannot create directory at \"${app_path}\"!"
  cat <<EOF > "${app_path}/metadata/local.meta"
[]
access = read : [ * ], write : [ admin ]
export = system
EOF
  cat <<EOF > "${app_path}/local/app.conf"
[install]
state = enabled

[package]
check_for_updates = false

[ui]
is_visible = false
is_manageable = false
EOF

if [[ "APP_TEMPLATE" != "$1" ]]; then
  build_app "$1"
fi

}

build_app () {
  app_path="${PROJ_DIR}/${PROJ_PREFIX}_$1"
  if [[ -d "$app_path" ]]; then
    build_"${1}" "$1" && build_success "${PROJ_PREFIX}_$1" || build_warn "Failed to build ${PROJ_PREFIX}_$1"
  fi
}

# Default OS configs
build_default_os_config() {
  mkdir -p "${PROJ_DIR}/default_os_config" || build_warn "${PROJ_DIR}/default_os_config failed to build!"
  default_base="${PROJ_DIR}/default_os_config"

  echo <<EOF > ${default_base}/thp.txt
#SPLUNK: disable THP at boot time
# Place this file in /etc/rc.d/rc.local
# add executable permissions with \`[sudo] chmod +x /etc/rc.d/rc.local\`

THP=\`find /sys/kernel/mm/ -name transparent_hugepage -type d | tail -n 1\`
for SETTING in "enabled" "defrag"; do
  if test -f \${THP}/\${SETTING}; then
    echo never > \${THP}/\${SETTING}
  fi
done
EOF

  cat <<EOF > ${default_base}/ulimits.txt
# Append the following configurations into /etc/security/limits.conf

splunk hard core 0
splunk hard maxlogins 10
splunk soft nofile 65535
splunk hard nofile 65535
splunk soft nproc 20480
splunk hard nproc 20480
splunk soft fsize unlimited
splunk hard fsize unlimited
EOF

  cat <<EOF > ${default_base}/splunk_init.txt
## update splunk's '/etc/init.d/splunk' boot-start script with the following.
## (Replace everything after "RETVAL=0" with the below)

USER=splunk

. /etc/init.d/functions

# disable hugepages
disable_huge() {
 echo "disabling huge page support"
 THP=\`find /sys/kernel/mm/ -name transparent_hugepage -type d | tail -n 1\`
 for SETTING in "enabled" "defrag";do
     if test -f \${THP}/\${SETTING}; then
         echo never > \${THP}/\${SETTING}
     fi
 done
}


# change ulimits
change_ulimit() {
  ulimit -Hn 65535
  ulimit -Sn 65535
  ulimit -Hu 20480
  ulimit -Su 20480
  ulimit -Hf unlimited
  ulimit -Sf unlimited
}

splunk_start() {
  echo Starting Splunk...
  /bin/su - \${USER} -c '"/opt/splunk/bin/splunk" start --no-prompt --answer-yes'
  RETVAL=\$?
  [ \$RETVAL -eq 0 ] && touch /var/lock/subsys/splunk
}
splunk_stop() {
  echo Stopping Splunk...
  /bin/su - \${USER} -c '"/opt/splunk/bin/splunk" stop'
  RETVAL=\$?
  [ \$RETVAL -eq 0 ] && rm -f /var/lock/subsys/splunk
}
splunk_restart() {
  echo Restarting Splunk...
  /bin/su - \${USER} -c '"/opt/splunk/bin/splunk" restart'
  RETVAL=\$?
  [ \$RETVAL -eq 0 ] && touch /var/lock/subsys/splunk
}
splunk_status() {
  echo Splunk status:
  /bin/su - \${USER} -c '"/opt/splunk/bin/splunk" status'
  RETVAL=\$?
}
case "\$1" in
  start)
    disable_huge
    change_ulimit
    splunk_start
    ;;
  stop)
    splunk_stop
    ;;
  restart)
    disable_huge
    change_ulimit
    splunk_restart
    ;;
  status)
    splunk_status
    ;;
  *)
    echo "Usage: \$0 {start|stop|restart|status}"
    exit 1
    ;;
esac

exit \$RETVAL
EOF

  cat <<EOF > ${default_base}/bashrc.txt
## helpful ~/.bashrc for splunk
#History Control
HISTCONTROL=ignorespace
#Set SPLUNK_HOME
for SPLUNK_HOME in "/Applications/Splunk" "/Applications/SplunkForwarder" "/opt/splunk" "/opt/splunkforwarder" "/Applications/SplunkBeta" "/Applications/SplunkForwarderBeta
" "\${HOME}/splunkforwarder";do
 if [ -d \${SPLUNK_HOME} ]; then
 break
 fi
done
if [ "\${SPLUNK_HOME}" == "" ];then
 echo "WARNING: SPLUNK_HOME env variable undefined"
fi
export SPLUNK_HOME
#Add splunk to PATH
export PATH=\$PATH:/usr/bin:\$SPLUNK_HOME/bin
#Add btool to PATH
KERNEL=\`uname -s\`
case "x\$KERNEL" in
 "xLinux")
 if [ -f /etc/lsb-release -o -d /etc/lsb-release.d ]; then
 export DISTRO=\$(lsb_release -i | cut -d: -f2 | sed s/^\t//)
 else
 export DISTRO=\$(ls -d /etc/[A-Za-z]*[_-][rv]e[lr]* | grep -v "lsb" | cut -d/ -f3 | cut -d- -f1 | cut -d_ -f1)
 fi
 if [ "x\$DISTRO" != "xUbuntu" ];then
 export LD_LIBRARY_PATH=\$SPLUNK_HOME/lib
 fi
 ;;
 "xDarwin")
 export DYLD_LIBRARY_PATH=\$SPLUNK_HOME/lib
 ;;
 *)
 echo "ERROR: Unable to set LIBRARY_PATH"
 exit 1
 ;;
esac
#Prompt String 1 (PS1)
PS1="[\`date\`] [\u@\h \w]\n> "
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
EOF
}

# helpers.
faillog() {
  echo "$1" >&2
}

fail() {
  faillog "[ ERROR ]   $@"
  exit 1
}

build_success() {
  echo "[ SUCCESS ] $@"
}

build_info() {
  echo "[ INFO ]    $@"
}

build_warn() {
  echo "[ WARN ]    $@"
}

error_checks() {
  shc_peers=($SHC_PEERS)
  test -z "$PROJ_NAME" && fail "No Project Name!"
  test -z "$PROJ_PREFIX" && fail "No Project Prefix!"
  test -z "$DS_IP" && build_warn "No Deployment Server Entered"
  if [[ $IS_CLUSTERED -gt 0 ]]; then
    ### Cluster variable error checks.
    test -z "$IDX_CM_IP" && build_warn "No Cluster Master IP Entered!"
    test -z "$IDX_SF" && build_warn "No Search Factor Entered!"
    test -z "$IDX_RF" && build_warn "No Replication Factor Entered!"
    test "$IDX_RF" -lt "$IDX_SF" && build_warn "Replication Factor Should be greater than Search Factor; RF: $IDX_RF, SF: $IDX_SF"
    test -z "$IDX_REP_PORT" && build_warn "Indexer replication port not specified!"
    test -z "$IDX_LABEL" && build_warn "Indexer cluster label not specified!"
  fi
  if [[ $IS_SH_CLUSTERED -gt 0 ]]; then
    test -z "$SHC_DR_IP" && build_warn "No SHC Deployer IP Entered!"
    test -z "$SHC_REP_PORT" && build_warn "No SHC Replication Port Entered!"
    test -z "$SHC_REP_FACTOR" && build_warn "No SHC Replication Factor Entered!"
    test -z "$SHC_LABEL" && build_warn "No SHC Label Entered!"
    test -z "$SHC_PEERS" && build_warn "No SHC Peers Entered!"
    test "${#shc_peers[@]}" != "$SHC_REP_FACTOR" && build_warn "The number of SHC peers does not match the replication factor. Number of SHC peers: ${#shc_peers[@]}, Rep Factor: $SHC_REP_FACTOR"
  fi
}

# Welcome
echo "======================================================================"
echo
echo "Welcome!"
echo
echo "This script will assist you in building your base config apps."
echo
echo "Remember: Trust, but verify ;)"
echo
echo "======================================================================"

build_setup() {
  # Collect Information for project
  echo
  echo "What is the name for the project?"
  echo "   This name will be used to create a directory to save the project   "
  read PROJ_NAME

  echo
  echo "What should the prefix for the project be?"
  echo "    This will replace the (org_)"
  read PROJ_PREFIX

  # Default Splunk Ports
  echo
  echo "Change Default Splunk Management Port (8089)? (Y/n)"
  read answer
  if [[ [Yy]* =~ "$answer" ]]; then
    echo "Please enter the new management port"
    read MGMT_PORT
  fi

  echo
  echo "Change Default Splunk Listen Port (9997)? (Y/n)"
  read answer
  if [[ [Yy]* =~ "$answer" ]]; then
    echo "Please enter the new listen port"
    read IDX_LISTEN_PORT
  fi

  ## Deployment Server
  echo
  echo "What is the IP of the Deployment Server? (e.g. 172.16.34.125)"
  read DS_IP
  echo

  ## For Indexer Clusters
  echo
  echo "Will there be an indexer cluster? (Y/n)"
  read is_cluster
  if [[ [Yy]* =~ "$is_cluster" ]]; then
    IS_CLUSTERED=1
    echo "Multisite Cluster? (Y/n)"
    read is_multisite_cluster
    if [[ [Yy] =~ $is_multisite_cluster ]]; then
      IS_MULTISITE=1
    else
      IS_MULTISITE=0
    fi
    echo "IDX Cluster - What is the IP for the Cluster Master"
    read IDX_CM_IP
    echo "IDX Cluster - What is the Replication Factor (RF)"
    read IDX_RF
    echo "IDX Cluster - What is the Search Factor (SF)"
    read IDX_SF
    echo "IDX Cluster - What is the replication port?"
    read IDX_REP_PORT
    echo "IDX Cluster - What is the cluster label? (Leave blank for none)"
    read IDX_LABEL
  else
    IS_CLUSTERED=0
  fi

  ## For SH Clusters
  echo
  echo "Will there be a search head cluster? (Y/n)"
  read is_sh_cluster
  if [[ [Yy]* =~ "$is_sh_cluster" ]]; then
    IS_SH_CLUSTERED=1
    echo "SHC - What is the IP for the Deployer?"
    read SHC_DR_IP
    echo "SHC - What is the Replication Port?"
    read SHC_REP_PORT
    echo "SHC - What is the Replication Factor?"
    read SHC_REP_FACTOR
    echo "SHC - What is the Cluster Label? (Leave blank for none)"
    read SHC_LABEL
    echo "SHC - Please list all SHC peers (space-seperated)(e.g. 172.16.34.12 172.16.34.13 172.16.34.14)"
    read SHC_PEERS
  else
    IS_SH_CLUSTERED=0
  fi

  # error checks
  echo
  error_checks
}

# Run Through the build setup
build_setup

# Preview before building
echo
echo "Please review carefully before proceeding!"
echo "The configuration is as follows:"
echo "========================================="
cat <<EOF
Project Name                 : $PROJ_NAME
Project Prefix               : $PROJ_PREFIX
Management Port              : $MGMT_PORT
Listen Port                  : $IDX_LISTEN_PORT
Deployment Server IP         : $DS_IP
Indexer Cluster              : $IS_CLUSTERED
Multisite                    : $IS_MULTISITE
Cluster Master IP            : $IDX_CM_IP
Search Factor                : $IDX_SF
Replication Factor           : $IDX_RF
IDX Cluster Replication Port : $IDX_REP_PORT
IDX Cluster Label            : $IDX_LABEL
Search Head Cluster          : $IS_SH_CLUSTERED
SHC Deployer IP              : $SHC_DR_IP
SHC Rep Port                 : $SHC_REP_PORT
SHC Rep Factor               : $SHC_REP_FACTOR
SHC Label                    : $SHC_LABEL
SHC Peers                    : $SHC_PEERS
EOF
echo "========================================="
echo "continue? (Y/n/quit)"
echo "Entering no will start the setup process from the beginning"
while true
do
  read answer
  case $answer in
    [yY]* ) break;;
    [nN]* ) echo "Starting over..."; build_setup;;
    [qQ]* ) echo "Goodbye.."; exit;;
    * ) echo "Please select yes to continue, no to try again, or quit to exit.";;
  esac
done

# Build Project
echo
echo "===================="
echo "     Building       "
echo "===================="
# Create Project Directory Structure
PROJ_DIR="projects/$PROJ_NAME"
PROJ_APP_PATH="${PROJ_DIR}/${PROJ_PREFIX}"
if [ ! -d "$PROJ_DIR" ]; then
  mkdir -p "$PROJ_DIR" || fail "Cannot create directory at \"$PROJ_DIR\"!"
else
  fail "Project Name (${PROJ_NAME}) already exists!"
fi
build_success "Project Directory"
build_app_base "APP_TEMPLATE"
build_app_base "all_indexes"
build_app_base "all_indexer_base"
build_app_base "indexer_volume_indexes"
build_app_base "all_deployment_client"
build_app_base "all_search_base"
build_app_base "search_volume_indexes"
if [[ "$IS_CLUSTERED" -gt 0 ]]; then
  build_app_base "cluster_forwarder_outputs"
  build_app_base "cluster_search_base"
  build_app_base "master_deploymentclient"
  if [[ "$IS_MULTISITE" -gt 0 ]]; then
    build_app_base "multisite_master_base"
    build_app_base "site_n_indexer_base"
  else
    build_app_base "cluster_indexer_base"
    build_app_base "cluster_master_base"
  fi
else
  build_app_base "all_forwarder_outputs"
fi
if [[ "$IS_SH_CLUSTERED" -gt 0 ]]; then
  build_app_base "sh_cluster_deployer_base"
fi
build_default_os_config

# Fin
echo
echo "--> Success <--"
echo "You are a rockstart"
