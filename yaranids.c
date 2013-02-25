#include <pcap/pcap.h>
#include <stdio.h>
#include <nids.h>
#include <syslog.h>
#include <yara.h>
#include <unistd.h>

char global_errbuf[1024];
YARA_CONTEXT *pcap_yr_ctx, *ip_yr_ctx, *tcp_yr_ctx, *udp_yr_ctx;

int
yaranids_pcap_yr_handler(RULE *rule, void *data) {
}

int
yaranids_ip_yr_handler(RULE *rule, void *data) {
}

int
yaranids_tcp_yr_handler(RULE *rule, void *data) {
  if(rule->flags & RULE_FLAGS_MATCH)
    printf("Matched TCP data: %s\n", rule->identifier);
}

int
yaranids_udp_yr_handler(RULE *rule, void *data) {
  if(rule->flags & RULE_FLAGS_MATCH)
    printf("Matched UDP data: %s\n", rule->identifier);
}

void
yaranids_ip_frag_handler(struct ip *pkt, int len) {
  //printf("IP Fragment Packet!\n");
}

void
yaranids_ip_handler(struct ip *pkt, int len) {
  //printf("IP Packet!\n");

  if(ip_yr_ctx != NULL)
    yr_scan_mem(pkt, (unsigned int)len, ip_yr_ctx, &yaranids_ip_yr_handler, pkt);
}

void
yaranids_tcp_handler(struct tcp_stream *ts, void **param) {
  //printf("TCP Stream!\n");

  switch(ts->nids_state) {
    case NIDS_JUST_EST:
      printf("Established!\n");
      ts->server.collect++;
      ts->server.collect_urg++;
      ts->client.collect++;
      ts->client.collect_urg++;
      break;
    case NIDS_CLOSE:
    case NIDS_TIMED_OUT:
    case NIDS_RESET:
      if(tcp_yr_ctx != NULL) {
        printf("Stopped (%s) (%d)!\n", ts->server.data, ts->server.count);
        yr_scan_mem(ts->client.data, ts->client.count, tcp_yr_ctx, &yaranids_tcp_yr_handler, &ts->client);
        yr_scan_mem(ts->server.data, ts->server.count, tcp_yr_ctx, &yaranids_tcp_yr_handler, &ts->server);
      }
      break;
  }
}

void
yaranids_udp_handler(struct tuple4 *addr, uint8_t *data, int len, struct ip *pkt) {
  //printf("UDP packet!\n");

  if(udp_yr_ctx != NULL)
    yr_scan_mem(data, (unsigned int)len, udp_yr_ctx, &yaranids_udp_yr_handler, data);
}

void
yaranids_pcap_handler(uint8_t *userval, const struct pcap_pkthdr *hdr, const uint8_t *bytes) {
  //printf("PCAP Packet!\n");

  /* Fork it over to libnids */
  nids_pcap_handler(userval, hdr, bytes);
}

void
init_nids_params(pcap_t *pcap_handle) {
  nids_params.n_tcp_streams = 1024;
  nids_params.n_hosts = 256;
  nids_params.filename = NULL;
  //nids_params.device = "msk0";
  nids_params.device = "wlan0";
  nids_params.sk_buff_size = 168;
  nids_params.dev_addon = -1;
  nids_params.syslog_level = LOG_ALERT;
  nids_params.scan_num_hosts = 0;
  nids_params.no_mem = NULL;
  nids_params.pcap_desc = pcap_handle;
  nids_params.tcp_workarounds = 0;
  nids_init();

  //nids_register_ip_frag(&yaranids_ip_frag_handler);
  nids_register_ip(&yaranids_ip_handler);
  nids_register_tcp(&yaranids_tcp_handler);
  nids_register_udp(&yaranids_udp_handler);
}

void
init_pcap(pcap_t *pcap_handle) {
  pcap_set_buffer_size(pcap_handle, 65536);
  pcap_set_snaplen(pcap_handle, 1500);
  pcap_set_promisc(pcap_handle, 1);
  pcap_set_timeout(pcap_handle, 900);
}

void
init_yara(void) {
  FILE *rfile;

  yr_init();

  pcap_yr_ctx = ip_yr_ctx = tcp_yr_ctx = udp_yr_ctx = NULL;

  /* Load static rules files */
  if(access("pcap_rules.yar", R_OK) == 0) {
    pcap_yr_ctx = yr_create_context();
    rfile = fopen("pcap_rules.yar", "rb");
    yr_compile_file(rfile, pcap_yr_ctx);
    fclose(rfile);
  }
  if(access("ip_rules.yar", R_OK) == 0) {
    ip_yr_ctx = yr_create_context();
    rfile = fopen("ip_rules.yar", "rb");
    yr_compile_file(rfile, ip_yr_ctx);
    fclose(rfile);
  }
  if(access("tcp_rules.yar", R_OK) == 0) {
    tcp_yr_ctx = yr_create_context();
    rfile = fopen("tcp_rules.yar", "rb");
    yr_compile_file(rfile, tcp_yr_ctx);
    fclose(rfile);
  }
  if(access("udp_rules.yar", R_OK) == 0) {
    udp_yr_ctx = yr_create_context();
    rfile = fopen("udp_rules.yar", "rb");
    yr_compile_file(rfile, udp_yr_ctx);
    fclose(rfile);
  }
}

int main(int argc, char **argv) {
  pcap_t *pcap_handle;

  init_yara();

  pcap_handle = pcap_create("wlan0", global_errbuf);
  //pcap_handle = pcap_create("msk0", global_errbuf);

  init_pcap(pcap_handle);
  pcap_activate(pcap_handle);
  init_nids_params(pcap_handle);

  pcap_loop(pcap_handle, -1, &yaranids_pcap_handler, NULL);
}

