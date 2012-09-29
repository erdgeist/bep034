#ifdef _WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include "lookup_bep_034.h"

/* worker threads, sane default for the usual amount of trackers */
#define WORKER_THREADS 8

void my_callback( bep034_lookup_id lookup_id, bep034_status status, const char * announce_url) {
  printf( "%d yields status: %s.\n The URL to use is:  %s\n", lookup_id, bep034_status_to_name[status], announce_url );
}

int main( int argc, char ** argv ) {
  bep034_register_callback( my_callback, WORKER_THREADS );
  bep034_lookup( "http://erdgeist.org:80/arts/software/opentracker/announce" );
  bep034_lookup( "http://erdgeist.org/arts/software/opentracker:199/announce" );
  bep034_lookup( "udp://foo:bar@tracker.ccc.de:90/" );
  bep034_lookup( "udp://foo:bar@tracker.ccc.de:90/" );
  bep034_lookup( "[2001::7]" );
  bep034_lookup( "[2001::7]:70/tracker/announce" );
  bep034_lookup( "127.0.0.1" );
  bep034_lookup( "udp://tracker.openbittorrent.com" );
  bep034_lookup( "http://tracker.openbittorrent.com" );
  bep034_lookup( "xmpp://erdgeist@erdgeist.org" );
  bep034_lookup( "http://erdgeist@erdgeist.org:a/" );

  /* Hang around for a while */
#ifndef _WIN32
  sleep(100);
#else
  Sleep(100000);
#endif

  return 0;
}
