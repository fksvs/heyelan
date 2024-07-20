#ifndef TCP_ATTACK_H
#define TCP_ATTACK_H

#include "types.h"

void attack_tcp_syn(struct target_data *target);
void attack_tcp_ack(struct target_data *target);

#endif
