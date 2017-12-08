
#ifndef _NGX_HTTP_FLV_LIVE_H_INCLUDED_
#define _NGX_HTTP_FLV_LIVE_H_INCLUDED_
#include "ngx_rtmp.h"




typedef struct {
	ngx_flag_t http_flv_live;
}ngx_http_flv_live_loc_conf_t;

typedef struct {
	ngx_flag_t http_flv_live;

	ngx_str_t port_from;
	ngx_str_t app_name;
	ngx_str_t st_name;

	unsigned  sent_header:1;
	ngx_rtmp_session_t *s;
	ngx_chain_t       *free;
	
}ngx_http_flv_live_ctx_t;


#endif 

