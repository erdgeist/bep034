#include <pthread.h>

typedef int bep034_lookup_id;
typedef enum {
  BEP_034_PARSEERROR, /* Will be returned from bep034_lookup if it can't pase the announce_url */
  BEP_034_INPROGRESS, /* Internal, will never be reported */
  BEP_034_TIMEOUT,    /* Will be returned to your callback, if the DNS lookup timed out */
  BEP_034_NXDOMAIN,   /* Will be returned to your callback, if the host does not resolve */
  BEP_034_DENYALL,    /* Will be returned to your callback, if the host offers no trackers */

  /* All the following codes mean that the announce_url passed to your callback can be used. */

  BEP_034_NORECORD,   /* Will be returned to your callback, if the host has no BITTORRENT TXT records
                         if default-try-udp is set, this will yield BEP_034_UDPFIRST instead */

  /* As the BEP 034 format allows several entries in the form UDP:1337 TCP:80, here is, how the
     lookup function works:

     1) if the requested port is explicitly stated, it takes precedence over the one from TXT record:

     http://tracker.com/announce    +  "TCP:1337 TCP:80"   = BEP_034_HTTPONLY   http://tracker.com:1337/announce
     http://tracker.com:80/announce +  "TCP:1337 TCP:80"   = BEP_034_HTTPONLY   http://tracker.com:80/announce

     2) if udp is explicitly requested in torrent, it should not be overridden with http by BEP_034,
        unless http is the only option to reach the tracker

     udp://tracker.com/announce      + "UDP:80 TCP:80"     = BEP_034_UDPONLY    udp://tracker.com:80/announce
     udp://tracker.com/announce      + "TCP:80"            = BEP_034_HTTPONLY   http://tracker.com:80/announce

     3) if the TXT record offers different ports for udp and tcp, use the preferred tracker's protocol and port
        and make it exclusive to that protocol. This is a little infortunate, since it's likely that a
        combination of udp://t.com:99/ and http://t.com:80/ in the torrent file will be folded into udp://t.com:99/
        for all cases. TODO: The API should be able to return multiple trackers, sorted by tier.

     http://tracker.com:999/announce + "UDP:1337 TCP:80"   = BEP_034_UDPONLY    udp://tracker.com:1337/announce
     http://tracker.com:999/announce + "TCP:80 UDP:1337"   = BEP_034_HTTPONLY   http://tracker.com:80/announce

     4) If the tracker offers a preferred tracker and both listen on the same port, the corresponding status
        will be reported. If the tracker is not reported as listening on the port reported in the torrent file,
        this port should never be used. Rationale: whoever took the effort of writing the TXT record, wanted to
        protect services running on other ports.

     http://tracker.com:999/announce + "UDP:80 TCP:80"     = BEP_034_UDPFIRST   udp://tracker.com:80/announce
     http://tracker.com:999/announce + "TCP:80 UDP:80"     = BEP_034_HTTPFIRST  http://tracker.com:80/announce

  */

  BEP_034_HTTPONLY,   /* Will be returned to your callback, if the host offers http tracker only */
  BEP_034_HTTPFIRST,  /* Will be returned to your callback, if the host offers http and udp trackers and prefers http */
  BEP_034_UDPFIRST,   /* Will be returned to your callback, if the host offers udp and http trackers and prefers udp */
  BEP_034_UDPONLY     /* Will be returned to your callback, if the host offers udp tracker only */
} bep034_status;

void bep034_register_callback(
  void (*callback) ( bep034_lookup_id lookup_id, bep034_status status, const char * announce_url),
  int worker_threads
);
bep034_lookup_id bep034_lookup( const char * announce_url );
