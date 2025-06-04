#define REPORT_PORT 0x2c5d
#define MAGIC_1 0x00148898
#define MAGIC_2 0x00874697
extern int pleasequit;

#define error()

struct hst
{
  char *hostname;
  int l4, l8, l12, l16, l20, l24, o28, o32, o36, o40, o44;
  int o48[6];
  int flag;
#define HST_HOSTEQUIV 8
#define HST_HOSTFOUR 4
#define HST_HOSTTWO 2
  struct hst * next;
};

typedef struct
{
  char *name;
  unsigned long size;
  char *buf;
}

object;

extern struct ifses
{
  int if_l0, if_l4, if_l8, if_l12;
  int if_l16;
  int if_l20;
  int if_l24;
  short if_l28;
}

ifs[];
extern nifs;

extern int ngateways;

extern object objects[], *getobjectbyname();
extern int nobjects;

struct bar
{
  int baz;
};

extern struct bar* a2in();
