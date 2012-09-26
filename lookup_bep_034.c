/* Standard C stuff */
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* OSX specific monotonic time functions */
#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#include <dns.h>
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

typedef struct bep034_job {
  bep034_lookup_id    lookup_id;
  bep034_status       status;
  int                 proto;     // 0 for http, 1 for udp
  uint16_t            port;      // 0 for not explicitly stated
  char              * userinfo;
  char              * hostname;
  char              * announce_path;
  char              * announce_url;
  struct bep034_job * next;
} bep034_job;
/* Linked list guarded by bep034_lock */
static bep034_job * bep034_joblist;
static int          bep034_jobnumber;

typedef struct {
  char            *hostname;
  time_t           expiry;        // Calculate from DNS TTL, how long the cache is valid
  int              entries;
  uint32_t         trackers[0];   // lower 16 bit port, higher 16 bit proto
} bep034_hostrecord;
/* Host record array guarded by bep034_lock */
static bep034_hostrecord ** bep034_hostrecordlist;
static size_t bep034_hostrecordcount;

/********************************

  Forward declarations

*********************************/

static void        * bep034_worker();
static int           bep034_pushjob( bep034_job * job );
static bep034_job  * bep034_getjob();
static void          bep034_finishjob( bep034_job * job );
static void          bep034_dumpjob( bep034_job * job );

static bep034_hostrecord * bep034_find_hostrecord( const char * hostname, int * index );
static bep034_status bep034_fill_hostrecord( const char * hostname, bep034_hostrecord ** hostrecord, uintptr_t dns_handle );
static int           bep034_save_record( bep034_hostrecord ** hostrecord );
static void          bep034_dump_record( bep034_hostrecord * hostrecord );
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

  /* Be sure to init libresolv before workers compete for
     calling res_init() from res_search */
#ifndef __MACH__
  res_init();
#endif

  pthread_mutex_lock( &bep034_lock );
  g_callback = callback;

  while( worker_threads-- )
    pthread_create( &thread_id, NULL, bep034_worker, NULL );
  pthread_mutex_unlock( &bep034_lock );

}

/* This function expects the bep034_lock to be held by caller,
   it assumes job to be on stack, fills out lookup_id, takes
   a copy and links it to the job list */
static int bep034_pushjob( bep034_job * job ) {
  bep034_job * newjob = malloc( sizeof( bep034_job ) );

  if( !newjob )
    return -1;

  job->lookup_id = ++bep034_jobnumber;
  bep034_dumpjob( job );

  memcpy( newjob, job, sizeof( bep034_job ) );

  newjob->next = bep034_joblist;
  bep034_joblist = newjob;

  /* Wake up sleeping workers */
  pthread_cond_signal( &bep034_cond );

  return 0;
}

/* This function expects the bep034_lock to be held by caller,
   it marks the job as taken by removing the pointer from linked list */
static bep034_job * bep034_getjob() {
  bep034_job ** job = &bep034_joblist, * outjob;

  while( !bep034_joblist )
    pthread_cond_wait( &bep034_cond, &bep034_lock);

  while( (*job)->next )
    job = &(*job)->next;

  outjob = *job;
  *job = 0;

  return outjob;
}

/* Clean up structure */
static void bep034_finishjob( bep034_job * job ) {
  if( job ) {
    free( job->userinfo );
    free( job->hostname );
    free( job->announce_path );
    free( job->announce_url );
  }
  free( job );
}

static void bep034_dumpjob( bep034_job * job ) {
  printf( "Parsed job info %d:\n Status: %d (%s)\n Proto: %s\n Port: %d\n Userinfo: %s\n Hostname: %s\n Path: %s\n Original URL: %s\n",
    job->lookup_id, job->status, bep034_status_to_name[job->status], job->proto ? "UDP" : "HTTP", job->port,
    job->userinfo ? job->userinfo : "(none)", job->hostname ? job->hostname : "(none)",
    job->announce_path ? job->announce_path : "(none)", job->announce_url );
}


/************ Host record handlers *************/

/* This function expects the bep034_lock to be held by caller */
static bep034_hostrecord * bep034_find_hostrecord( const char * hostname, int * index ) {
  /* Linear search for now, have sorted list later */
  for( *index=0; *index < bep034_hostrecordcount; ++*index ) {
    bep034_hostrecord * hr = bep034_hostrecordlist[*index];

    if( !strcasecmp( hr->hostname, hostname ) ) {
      /* If the entry is not yet expired, return it */
      if( NOW() <= hr->expiry )
        return hr;

      free( hr->hostname );
      free( hr );

      memmove( bep034_hostrecordlist + *index, bep034_hostrecordlist + 1,
        ( bep034_hostrecordcount - *index ) * sizeof( bep034_hostrecord * ) );

      /* Shrinking always succeeds */
      bep034_hostrecordlist = realloc( bep034_hostrecordlist,
        --bep034_hostrecordcount * sizeof( bep034_hostrecord *) );

      /* Since we assume our array to be unique, we can stop here */
      return 0;
    }
  }

  return 0;
}

/* This function expects the bep034_lock to be held by caller,
   it takes the ownership of the hostrecord object on call and
   frees it on error */
static int bep034_save_record( bep034_hostrecord ** hostrecord ) {
  int index;
  bep034_hostrecord * hr = bep034_find_hostrecord( (*hostrecord)->hostname, &index );
  bep034_hostrecord ** new_hostrecordlist;

  /* If we do know about this host already, check which entry expires earlier
     and use the one that lasts longer */
  if( hr ) {
    if( hr->expiry < (*hostrecord)->expiry ) {
      free( hr->hostname );
      free( hr );
      bep034_hostrecordlist[ index ] = *hostrecord;
    } else {
      free( (*hostrecord)->hostname );
      free( *hostrecord );
      *hostrecord = hr;
    }
    return 0;
  }

  /* Make room for the new host record and store it there */
  new_hostrecordlist =
    realloc( bep034_hostrecordlist, bep034_hostrecordcount * sizeof( bep034_hostrecord *) );

  /* If we can not rellocate, there's no place to store the host record to,
     signal an error and deallocate the host record */
  if( !new_hostrecordlist ) {
    free( (*hostrecord)->hostname );
    free( *hostrecord );
    return -1;
  }

  /* Use newly allocated host record list from now on */
  bep034_hostrecordlist = new_hostrecordlist;

  /* Everything went fine. Store new host record as last entry
     TODO: Sort entries */
  bep034_hostrecordlist[bep034_hostrecordcount++] = *hostrecord;

  return 0;
}

static void bep034_dump_record( bep034_hostrecord * hostrecord ) {
  int i;
  printf( "Hostname: %s\n Expiry in s: %ld\n", hostrecord->hostname, (long)(hostrecord->expiry - NOW()) );
  for( i=0; i<hostrecord->entries; ++i ) {
    printf( " Tracker at: %s Port %d\n", ( hostrecord->trackers[i] & 0x10000 ) ? "UDP " : "HTTP", hostrecord->trackers[i] & 0xffff );
  }
  putchar( 10 );
}

/* This function expects the bep034_lock to be held by caller,
   releases it while working and returns with the lock held
*/
static bep034_status bep034_fill_hostrecord( const char * hostname, bep034_hostrecord ** hostrecord, uintptr_t dns_handle ) {
  uint8_t answer[NS_PACKETSZ];
  bep034_hostrecord * hr = 0;
  int answer_len, num_msgs, max_entries, i;
  ns_msg msg;
  ns_rr rr;

  /* Reset hostrecord pointer */
  * hostrecord = 0;

  /* If we find a record in cache, return it */
  hr = bep034_find_hostrecord( hostname, &i /* dummy */ );
  if( hr ) {
    *hostrecord = hr;
    return BEP_034_INPROGRESS;
  }

  /* Return mutex, we'll be blocking now and do not
     hold any resources in need of guarding  */
  pthread_mutex_unlock( &bep034_lock );

  /* Query resolver for TXT records for the trackers domain */
#ifdef __MACH__
  {
    struct sockaddr tmp;
    uint32_t tmplen;
    answer_len = dns_search( (dns_handle_t)dns_handle, hostname, ns_c_in, ns_t_txt, answer, sizeof(answer), &tmp, &tmplen );
  }
#else
  (void)dns_handle;
  answer_len = res_search(hostname, ns_c_in, ns_t_txt, answer, sizeof(answer));
#endif
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
  for( i=0; i<num_msgs; ++i) {
    ns_parserr (&msg, ns_s_an, i, &rr);
    if (ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_txt ) {
      uint32_t record_ttl = ns_rr_ttl(rr);
      uint16_t record_len = ns_rr_rdlen(rr);
      const uint8_t *record_ptr = ns_rr_rdata(rr);
      const char * string_ptr, * string_end;

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
        uint32_t port = 0;

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

      /* Ensure exclusive access to the host record list, lock will be held
         on return so that the caller can work with hr */
      pthread_mutex_lock( &bep034_lock );

      /* Hand over record to cache, from now the cache has to release memory */
      if( bep034_save_record( &hr ) )
        return BEP_034_TIMEOUT;

      /* Dump what we found */
      bep034_dump_record( hr );

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
#ifdef __MACH__
  dns_handle_t dns_handle = dns_open(0);
#else
  void *dns_handle = 0;
#endif
  pthread_mutex_lock( &bep034_lock );
  while( 1 ) {
    bep034_job * myjob = 0;
    bep034_hostrecord * hr = 0;
    char * reply = 0;

    /* Waking up, grab one job from the work queue */
    myjob = bep034_getjob( );
    if( !myjob ) continue;

    /* Fill host record with results from DNS query or cache,
       owner of the hr is the cache, not us. This can block (but releases lock while blocking) */
    if( myjob->status == BEP_034_INPROGRESS )
      myjob->status = bep034_fill_hostrecord( myjob->hostname, &hr, (uintptr_t)dns_handle );

    /* Function returns with the bep034_lock locked, so that hr will
       be valid until we're finished with it */

   if( myjob->status == BEP_034_INPROGRESS ) {
      bep034_actonrecord( myjob, hr );
      bep034_build_announce_url( myjob, &reply );
   } else
      reply = strdup( myjob->announce_url );

    /* Return mutex */
    pthread_mutex_unlock( &bep034_lock );

    if( g_callback )
      g_callback( myjob->lookup_id, myjob->status, reply );
    free( reply );

    /* Clean up structure */
    bep034_finishjob( myjob );

    /* Acquire lock to  loop */
    pthread_mutex_lock( &bep034_lock );
  }
}

static bep034_status bep034_parse_announce_url( bep034_job *job ) {
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
      return (job->status = BEP_034_PARSEERROR);
    colon = strchr( closing_bracket, ':' );
  } else
    colon = strchr( announce_url, ':' );

  /* If colon is only after domain part, ignore it */
  if( slash && colon && colon > slash ) colon = 0;

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
    return (job->status = BEP_034_PARSEERROR);

  /* Everything from colon to eos must be digits */
  while( colon && *++colon ) {
    if( *colon >= '0' && *colon <= '9' )
      job->port = job->port * 10 + *colon - '0';
    else
      return (job->status = BEP_034_PARSEERROR);
  }

  if( !job->hostname || !*job->hostname )
    return (job->status = BEP_034_PARSEERROR);

  /* Avoid looking up v4/v6 URIs */
  if( *job->hostname == '[' )
    return (job->status = BEP_034_NORECORD);

  /* Candidates are hostnames starting with a digit */
  if( *job->hostname >= '0' && *job->hostname <= '9' ) {
    /* If TLD consists solely of digits, assume ipv4 address */
    char * dot = strrchr( job->hostname, '.' );
    if( !dot )
      return (job->status = BEP_034_INPROGRESS);

    while( *++dot )
      if( *dot < '0' || *dot > '9' )
        return (job->status = BEP_034_INPROGRESS);

    return (job->status = BEP_034_NORECORD);
  }

  return (job->status = BEP_034_INPROGRESS);
}

/************ The user API to kick off a lookup *************/

int bep034_lookup( const char * announce_url ) {
  bep034_job tmpjob;
  int res;

  /* Need a pristine struct */
  memset( &tmpjob, 0, sizeof(tmpjob));

  tmpjob.announce_url = strdup( announce_url );
  if( !tmpjob.announce_url )
    return -1;

  (void)bep034_parse_announce_url( &tmpjob );

  /* announce url might have been modified by parser */
  free( tmpjob.announce_url );
  tmpjob.announce_url = strdup( announce_url );

  /* Ensure exclusive access to the host record list */
  pthread_mutex_lock( &bep034_lock );

  /* The function takes a copy of our job object and
     fills in the lookup_id */
  res = bep034_pushjob( &tmpjob );
  pthread_mutex_unlock( &bep034_lock );

  /* Pushing may have failed */
  if( res )
    return res;

  return tmpjob.lookup_id;
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
  "Domain has no record. Also true for v4 or v6 addresses",
  "HTTP only",
  "HTTP first",
  "UDP only",
  "UDP first"
};


