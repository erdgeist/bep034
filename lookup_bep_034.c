/* Standard C stuff */
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* OSX specific monotonic time functions */
#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

/* DNS related includes */
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>

/* Our header files */
#include "lookup_bep_034.h"

static pthread_mutex_t bep034_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  bep034_cond = PTHREAD_COND_INITIALIZER;
static void (*g_callback) ( bep034_lookup_id lookup_id, bep034_status status, const char * announce_url );

typedef struct {
  bep034_lookup_id lookup_id;
  bep034_status    status;
  int              proto;     // 0 for http, 1 for udp
  uint16_t         port;      // 0 for not explicitly stated
  char            *userinfo;
  char            *hostname;
  char            *announce_path;
  char            *announce_url;
} bep034_job;

typedef struct {
  char            *hostname;
  time_t           expiry;        // Calculate from DNS TTL, how long the cache is valid
  int              entries;
  uint32_t         trackers[0];   // lower 16 bit port, higher 16 bit proto
} bep034_hostrecord;

/********************************

  Forward declarations

*********************************/

static void        * bep034_worker();
static int           bep034_pushjob( bep034_job * job );
static bep034_job  * bep034_getjob();
static void          bep034_finishjob( bep034_job * job );

static bep034_hostrecord * bep034_find_hostrecord( const char * hostname );
static bep034_status bep034_fill_hostrecord( const char * hostname, bep034_hostrecord ** hostrecord );
static int           bep034_save_record( bep034_hostrecord * hostrecord );
static void          bep034_actonrecord( bep034_job * job, bep034_hostrecord * hostrecord );
static void          bep034_build_announce_url( bep034_job * job, char ** announce_url );

/********************************

  End of declarations,
  begin of implementation

*********************************/

/************ static helpers ************/
static int NOW() {
#ifdef __MACH__ // OS X does not have clock_gettime, use clock_get_time
  /* Stolen from http://stackoverflow.com/questions/5167269/clock-gettime-alternative-in-mac-os-x */
  clock_serv_t cclock;
  mach_timespec_t now;
  host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
  clock_get_time(cclock, &now);
  mach_port_deallocate(mach_task_self(), cclock);
#else
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now );
#endif
  return now.tv_sec;
}

/************ Threading and job dispatch helpers ************/

void bep034_register_callback( void (*callback) ( bep034_lookup_id lookup_id, bep034_status status, const char * announce_url ), int worker_threads) {
  pthread_t thread_id;
  pthread_mutex_lock( &bep034_lock );
  g_callback = callback;
  while( worker_threads-- )
    pthread_create( &thread_id, NULL, bep034_worker, NULL );
  pthread_mutex_unlock( &bep034_lock );
}

static int bep034_pushjob( bep034_job * job ) {
  /* For now no job handling */
  return 1;
}

static bep034_job * bep034_getjob() {
  /* For now no job handling */
  return 0;
}

static void bep034_finishjob( bep034_job * job ) {
  /* For now no job handling */
  return;
}

/************ Host record handlers *************/

static bep034_hostrecord * bep034_find_hostrecord( const char * hostname ) {
  /* For now we do not have caching */
  return 0;
}

static int bep034_save_record( bep034_hostrecord * hostrecord ) {
  return 0;
}

static bep034_status bep034_fill_hostrecord( const char * hostname, bep034_hostrecord ** hostrecord ) {
  uint8_t answer[NS_PACKETSZ];
  bep034_hostrecord * hr = 0;
  int answer_len, num_msgs, max_entries, i;
  ns_msg msg;
  ns_rr rr;

  /* Reset hostrecord pointer */
  * hostrecord = 0;

  /* If we find a record in cache, return it */
  hr = bep034_find_hostrecord( hostname );
  if( hr ) {
    *hostrecord = hr;
    return BEP_034_INPROGRESS;
  }

  /* Query resolver for TXT records for the trackers domain */
  answer_len = res_search(hostname, ns_c_in, ns_t_txt, answer, sizeof(answer));
  if( answer_len < 0 ) {
    /* Here we enter race condition land */
    switch( h_errno ) {
    case NO_RECOVERY: case HOST_NOT_FOUND: return BEP_034_NXDOMAIN;
    case NO_DATA: return BEP_034_NORECORD;
    case NETDB_INTERNAL: case TRY_AGAIN: default: return BEP_034_TIMEOUT;
    }
  }

  ns_initparse (answer, answer_len, &msg);
  num_msgs = ns_msg_count (msg, ns_s_an);
  for (i = 0; i < num_msgs; ++i) {
    ns_parserr (&msg, ns_s_an, i, &rr);
    if (ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_txt ) {
      uint32_t record_ttl = ns_rr_ttl(rr);
      uint16_t record_len = ns_rr_rdlen(rr);
      const uint8_t *record_ptr = ns_rr_rdata(rr);
      const char * string_ptr, * string_end;
      uint32_t port = 0;

      /* First octet is length of (first) string in the txt record.
         Since BEP034 does not say anything about multiple strings,
         we ignore all but the first string in each TXT record. */
      uint8_t string_len = *record_ptr;

      /* If we would read beyond buffer end, ignore record */
      if( record_ptr + 1 + string_len > answer + answer_len )
        continue;

      /* Sanitize string length against record length */
      if( string_len + 1 > record_len )
        string_len = record_len - 1;

      /* Test if we are interested in the record */
      if( string_len < 10 /* strlen( "BITTORRENT" ) */ )
        continue;

      /* Although the BEP is not very specific, we interpret the wording
         "This should always be the first word in the record" as a requirment
         to not start the record with a space */
      if( memcmp( record_ptr + 1, "BITTORRENT", 10 ) )
        continue;

      /* We found a BITTORRENT TXT record. Now start parsing:
         Given entries of the form "UDP:\d+\s" i.e. 6 bytes,
         in a record of length N we have an upper bound of
         ( N - 11 ) / 6 records.
      */
      max_entries = 1 + ( string_len - 11 ) / 6;

      /* Allocate memory for host record */
      hr = (bep034_hostrecord*)
        malloc( sizeof(bep034_hostrecord) + sizeof( uint32_t ) * max_entries );
      if( !hr )
        return BEP_034_TIMEOUT;

      /* Init host record */
      hr->hostname = strdup( hostname );
      hr->entries = 0;
      hr->expiry = NOW() + record_ttl;

      /* Look for "\s(TCP|UDP):\d+" */
      string_ptr = record_ptr + 1;
      string_end = string_ptr + string_len;
      string_ptr += 10 /* strlen( "BITTORRENT" ) */;

      while( string_ptr + 6 < string_end ) { /* We need at least 6 bytes for a word */
        int found;
        ++string_ptr;
        if( string_ptr[-1] != ' ' || string_ptr[2] != 'P' || string_ptr[3] != ':' )
          continue;
        if( string_ptr[0] == 'T' && string_ptr[1] == 'C' )
          found = 0;
        else if( string_ptr[0] == 'U' && string_ptr[1] == 'D' )
          found = 1;
        else
          continue;

        /* Now we're sure, we've found UDP: or TCP: and assume, from string_ptr + 4 there's
           a port number*/
        string_ptr += 4;
        while( string_ptr < string_end && (*string_ptr >= '0' && *string_ptr <= '9' ) )
          port = port * 10 + *(string_ptr++) - '0';

        /* If no digit was found, word is invalid */
        if( string_ptr[-1] == ':' ) continue;

        /* If number did not terminate on end of string or with a space, word is invalid */
        if( string_ptr != string_end && *string_ptr != ' ' ) continue;

        /* If we have an invalid port number, word is invalid */
        if( port > 65335 ) continue;

        /* Valid word found, add it to tracker list */
        hr->trackers[ hr->entries++ ] = port | ( found ? 0x10000 : 0 );
      }

      /* Hand over record to cache, from now the cache has to release memory */
      if( bep034_save_record( hr ) )
        return BEP_034_TIMEOUT;

      /* Once the first line in the first record has been parsed, return host record */
      *hostrecord = hr;
      return BEP_034_INPROGRESS;
    }
  }
}

/************ The actual engine[tm] *************/

static void bep034_actonrecord( bep034_job * job, bep034_hostrecord * hostrecord ) {
  /* Here comes the code that modifies a job description accoring to the host record
     trackers */
  return;
}

static void bep034_build_announce_url( bep034_job * job, char ** announce_url ) {
  /* First check length required to compose announce url */
  size_t req_len = snprintf( 0, 0, "%s://%s%s%s:%d/%s",
    job->proto ? "http" : "udp", job->userinfo ? job->userinfo : "", job->userinfo ? "@" : "",
    job->hostname, job->port ? job->port : 80, job->announce_path ? job->announce_path : "" );

  *announce_url = malloc( req_len + 1 );
  if( !*announce_url ) return;

  snprintf( *announce_url, req_len + 1, "%s://%s%s%s:%d/%s",
    job->proto ? "http" : "udp", job->userinfo ? job->userinfo : "", job->userinfo ? "@" : "",
    job->hostname, job->port ? job->port : 80, job->announce_path ? job->announce_path : "" );
}

static void *bep034_worker() {
  pthread_mutex_lock( &bep034_lock );
  while( 1 ) {
    bep034_job * myjob = 0;
    bep034_hostrecord * hr = 0;
    char * reply = 0;
    int res;

    pthread_cond_wait( &bep034_cond, &bep034_lock);

    /* Waking up, grab one job from the work queue */
    myjob = bep034_getjob( );
    if( !myjob ) continue;

    pthread_mutex_unlock( &bep034_lock );

    /* Fill host record with results from DNS query or cache,
       owner of the hr is the cache, not us. This can block */
    res = bep034_fill_hostrecord( myjob->hostname, &hr );
    switch( res ) {
    case BEP_034_TIMEOUT:
    case BEP_034_NXDOMAIN:
    case BEP_034_DENYALL:
      myjob->status = res;
      break;
    default:
      if( hr ) {
        bep034_actonrecord( myjob, hr );
        bep034_build_announce_url( myjob, &reply );
      } else
        myjob->status = BEP_034_TIMEOUT;
      break;
    }
    if( g_callback )
      g_callback( myjob->lookup_id, myjob->status, reply );
    free( reply );

    /* Acquire lock to return the job as finished, loop */
    pthread_mutex_lock( &bep034_lock );
    bep034_finishjob( myjob );
  }
}

static bep034_status bep034_parse_announce_url( bep034_job *job ) {
  memset( job, 0, sizeof(job));
  char * slash, * colon, * at;
  char * announce_url = job->announce_url;

  /* Decompose announce url, if it does not start with udp:// or http://,
     assume it to be an http url starting with the host name */
  if( !strncasecmp( announce_url, "udp://", 6 ) ) {
    job->proto = 1;
    announce_url += 6;
  } else if( !strncasecmp( announce_url, "http://", 7 ) )
    announce_url += 7;

  /* the host name is everything up to the first / or the first colon */

  /* Search for first slash and a possible userinfo:password@ prefix */
  slash = strchr( announce_url, '/' );
  at = strchr( announce_url, '@' );

  if( at && ( !slash || at < slash ) ) {
    *at = 0;
    job->userinfo = strdup( announce_url );
    /* Point to after userinfo part */
    announce_url = at + 1;
  }

  /* Check for v6 address. Do it now so the v6 address' colons will not
     confuse the parser */
  if( *announce_url == '[' ) {
    const char * closing_bracket = strchr( announce_url, ']' );
    if( !closing_bracket )
      return BEP_034_PARSEERROR;
    colon = strchr( closing_bracket, ':' );
  } else
    colon = strchr( announce_url, ':' );

  /* This helps parsing */
  if( slash ) *slash = 0;
  if( colon ) *colon = 0;

  /* The host name should now be \0 terminated */
  job->hostname = strdup( announce_url );

  /* If we have a slash, treat everything following that slash as announce path,
     default to the standard path */
  if( slash )
    job->announce_path = strdup( slash + 1 );
  else
    job->announce_path = strdup( "announce" );

  /* If we've found a colon followed by a slash, we've very likely
     encountered an unknown scheme. Report a parse error */
  if( colon + 1 == slash )
    return BEP_034_PARSEERROR;

  /* Everything from colon to eos must be digits */
  while( colon && *++colon ) {
    if( *colon >= '0' && *colon <= '9' )
      job->port = job->port * 10 + *colon - '0';
    else
      return BEP_034_PARSEERROR;
  }

  if( !job->hostname || !*job->hostname )
    return BEP_034_PARSEERROR;

  /* Avoid looking up v4/v6 URIs */
  if( *job->hostname == '[' )
    return BEP_034_NORECORD;

  /* Candidates are hostnames starting with a digit */
  if( *job->hostname >= '0' && *job->hostname <= '9' ) {
    /* If TLD consists solely of digits, assume ipv4 address */
    char * dot = strrchr( job->hostname, '.' );
    if( !dot ) return BEP_034_INPROGRESS;

    while( *++dot ) if( *dot < '0' || *dot > '9' ) return BEP_034_INPROGRESS;

    return BEP_034_NORECORD;
  }

  return BEP_034_INPROGRESS;
}

/************ The user API to kick off a lookup *************/

int bep034_lookup( const char * announce_url ) {
  bep034_job tmpjob;
  tmpjob.announce_url = strdup( announce_url );
  if( !tmpjob.announce_url )
    return -1;

  tmpjob.status = bep034_parse_announce_url( &tmpjob );

  /* announce url might have been modified by parser */
  free( tmpjob.announce_url );
  tmpjob.announce_url = strdup( announce_url );

  bep034_pushjob( &tmpjob );

  return 0;
}

/********************************

  End of implementation,
  begin of external helpers

*********************************/

const char *bep034_status_to_name[] = {
  "Parse Error.",
  "In progress, i.e. OK so far",
  "Timeout, i.e. temporary failure",
  "NXDomain, i.e. host is unknown",
  "No trackers, i.e. host explicitely forbids tracker traffic",
  "HTTP only",
  "HTTP first",
  "UDP only",
  "UDP first"
};


