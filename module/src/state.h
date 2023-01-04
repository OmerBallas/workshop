#ifndef _STATE_H_
#define _STATE_H_

#include "fw.h"

unsigned int update_state(struct tcphdr* hdr, connection_table_row_t* ctr);
void update_state_local(struct tcphdr* hdr, connection_table_row_t* ctr);

#endif