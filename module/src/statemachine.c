#include "fw.h"
#include "state.h"


//state is the state of the sender
unsigned int update_state_listen(struct tcphdr* hdr, connection_table_row_t* ctr){
    if ((tcp_flag_word(hdr) & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
    {   
        ctr->state = STATE_SYN_RECIVED;
        return NF_ACCEPT;
    }
    return NF_DROP;
    
}

unsigned int update_state_syn_sent(struct tcphdr* hdr, connection_table_row_t* ctr){
    if ((tcp_flag_word(hdr) & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
    {
        return NF_DROP;
    }
    else if (tcp_flag_word(hdr) & (TCP_FLAG_ACK))
    {
        ctr->state = STATE_ESTABLISHED_TCP;
        ctr->twin->state = STATE_ESTABLISHED_TCP;
        if (hdr->dest == ntohs(80))
        {
            ctr->state = STATE_ESTABLISHED_HTTP;
            ctr->twin->state = STATE_ESTABLISHED_HTTP;
            ctr->proxy_state = STATE_ESTABLISHED_HTTP;
            ctr->twin->proxy_state = STATE_ESTABLISHED_HTTP;
            
        }
        if (hdr->dest == ntohs(21))
        {
            ctr->state = STATE_ESTABLISHED_FTP_CON;
            ctr->twin->state = STATE_ESTABLISHED_FTP_CON;
            ctr->proxy_state = STATE_ESTABLISHED_FTP_CON;
            ctr->twin->proxy_state = STATE_ESTABLISHED_FTP_CON;
        }
        if (hdr->source == ntohs(20))
        {
            ctr->state = STATE_ESTABLISHED_FTP_DATA;
            ctr->twin->state = STATE_ESTABLISHED_FTP_DATA;
        }
        
        
        return NF_ACCEPT;
    }
    return NF_DROP;
}

unsigned int update_state_syn_recived(struct tcphdr* hdr, connection_table_row_t* ctr){   
    return NF_DROP;
}

unsigned int update_state_close_wait(struct tcphdr* hdr, connection_table_row_t* ctr){
    if (tcp_flag_word(hdr) & (TCP_FLAG_FIN)){
        ctr->state = STATE_LAST_ACK;
        ctr->twin->state = STATE_FIN_WAIT_2;
        return NF_ACCEPT;
    }
    return NF_ACCEPT;
}

unsigned int update_state_fin_wait_1(struct tcphdr* hdr, connection_table_row_t* ctr){
    return NF_ACCEPT;
}
unsigned int update_state_fin_wait_2(struct tcphdr* hdr, connection_table_row_t* ctr){
    ctr->state = STATE_CLOSED;
    ctr->twin->state = STATE_CLOSED;
    return NF_ACCEPT;
}
unsigned int update_state_closed(struct tcphdr* hdr, connection_table_row_t* ctr){   
    return NF_DROP;
}
unsigned int update_state_established(struct tcphdr* hdr, connection_table_row_t* ctr){
    if (tcp_flag_word(hdr) & (TCP_FLAG_FIN)){
        ctr->state = STATE_FIN_WAIT_1;
        ctr->twin->state = STATE_CLOSE_WAIT;
        return NF_ACCEPT;
    }
    return NF_ACCEPT;
}
unsigned int proxy(struct tcphdr* hdr, connection_table_row_t* ctr){
    if (tcp_flag_word(hdr) & (TCP_FLAG_FIN)){
        if ((ctr->proxy_state == STATE_ESTABLISHED_HTTP) || (ctr->proxy_state == STATE_ESTABLISHED_FTP_CON))
        {
            ctr->proxy_state = STATE_FIN_WAIT_1;
            return NF_ACCEPT;
        }
        if (ctr->proxy_state == STATE_CLOSE_WAIT)
        {
            ctr->proxy_state = STATE_LAST_ACK;
            return NF_ACCEPT;
        }
 
        return NF_ACCEPT;
    }
    if (ctr->proxy_state == STATE_FIN_WAIT_2)
        {
            ctr->proxy_state = STATE_CLOSED;
            ctr->state = STATE_CLOSED;
            return NF_ACCEPT;
        }
    return NF_ACCEPT;
}


unsigned int update_state(struct tcphdr* hdr, connection_table_row_t* ctr){
    switch (ctr->state)
    {
    case STATE_LISTEN:
        return update_state_listen(hdr,ctr);
        break;
    case STATE_SYN_SENT:
        return update_state_syn_sent(hdr,ctr);
        break;
    case STATE_SYN_RECIVED:
        return update_state_syn_recived(hdr,ctr);
        break;
    case STATE_CLOSE_WAIT:
        return update_state_close_wait(hdr, ctr);
        break;
    case STATE_FIN_WAIT_1:
        return update_state_fin_wait_1(hdr, ctr);
        break;
    case STATE_FIN_WAIT_2:
        return update_state_fin_wait_2(hdr, ctr);
        break;
    case STATE_CLOSED:
        return update_state_closed(hdr , ctr);
        break;
    case STATE_ESTABLISHED_TCP:
        return update_state_established(hdr, ctr);
        break;
    case STATE_ESTABLISHED_FTP_DATA:
        return update_state_established(hdr,ctr);
    //proxy cases:
    default:
        return proxy(hdr,ctr);
        break;
    }
    
    
    //shouldn't get here
    return NF_DROP;
}

void update_state_local(struct tcphdr* hdr, connection_table_row_t* ctr){
    if (tcp_flag_word(hdr) & (TCP_FLAG_FIN)){
        if ((ctr->proxy_state == STATE_ESTABLISHED_HTTP) || (ctr->proxy_state == STATE_ESTABLISHED_FTP_CON))
        {
            ctr->proxy_state = STATE_CLOSE_WAIT;
            return;
        }
        
        if (ctr->proxy_state == STATE_FIN_WAIT_1)
        {
            ctr->proxy_state = STATE_FIN_WAIT_2;
            return;
        }
        
    }
    if (ctr->proxy_state == STATE_LAST_ACK)
        {
            ctr->proxy_state = STATE_CLOSED;
            ctr->state = STATE_CLOSED;
            return;
        }
    
}
