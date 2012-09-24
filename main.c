#include "lookup_bep_034.h"

/* worker threads, sane default for the usual amount of trackers */
#define WORKER_THREADS 8

void my_callback( bep034_lookup_id lookup_id, bep034_status status, const char * announce_url) {
  printf( "%d yields status: %s and url %s\n", lookup_id, status, announce_url );
}

int main( int argc, char ** argv ) {
  bep034_register_callback( my_callback, WORKER_THREADS );
  bep034_lookup( "http://erdgeist.org:80/arts/software/opentracker/announce" );

  /* Hang around for a while */
  sleep( 100 );

  return 0;
}
