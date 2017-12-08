#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_version.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_play_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_http_flv_live_module.h"

//#define WRITE_FLV_FILE

#ifdef WRITE_FLV_FILE
static ngx_fd_t         	g_fd = -1;
static ngx_int_t			g_count = 0;
#endif

//
extern u_char *ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len);

static void* ngx_http_flv_live_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_flv_live_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

static ngx_int_t ngx_http_flv_live_init(ngx_conf_t *cf);

static ngx_chain_t* ngx_http_flv_live_prepare_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_header_t *lh, ngx_chain_t *in);
static ngx_int_t ngx_http_flv_live_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        unsigned int priority);
static ngx_int_t ngx_http_flv_live_send_meta_and_header(ngx_rtmp_session_t *s, ngx_chain_t *meta_data,
        unsigned int priority);
static ngx_int_t ngx_http_flv_live_send_flv_header(ngx_rtmp_session_t *s);

static void ngx_http_flv_live_send(ngx_event_t *wev);
static void ngx_http_flv_live_read(ngx_event_t *rev);


static ngx_command_t  ngx_http_flv_live_commands[] = {

    { ngx_string("http_flv"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_flv_live_loc_conf_t, http_flv_live),
        NULL },
    ngx_null_command
};

static ngx_http_module_t  ngx_http_flv_live_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_flv_live_init,    /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_flv_live_create_loc_conf,      /* create location configuration */
    ngx_http_flv_live_merge_loc_conf,       /* merge location configuration */
};

ngx_module_t  ngx_http_flv_live_module = {
	NGX_MODULE_V1,
   &ngx_http_flv_live_module_ctx,		   /* module context */
   ngx_http_flv_live_commands,			   /* module directives */
   NGX_HTTP_MODULE, 				   /* module type */
   NULL,							   /* init master */
   NULL,							   /* init module */
   NULL,//ngx_http_flv_live_init_process,		   /* init process */
   NULL,							   /* init thread */
   NULL,							   /* exit thread */
   NULL,							   /* exit process */
   NULL,							   /* exit master */
   NGX_MODULE_V1_PADDING

};
static void*
ngx_http_flv_live_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_flv_live_loc_conf_t *hflf;
	hflf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flv_live_loc_conf_t));
	if(hflf == NULL){
		return NULL;
	}
	hflf->http_flv_live = NGX_CONF_UNSET;
	return hflf;
}
static char*	   
ngx_http_flv_live_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf)
{
	ngx_http_flv_live_loc_conf_t *prev_c, *cf_c;
	prev_c= prev;
	cf_c = conf;

	ngx_conf_merge_value(cf_c->http_flv_live, prev_c->http_flv_live, 0);
	
	return NGX_CONF_OK;		
}
/*获取appconf setconf*/
static ngx_int_t 
ngx_http_flv_live_init_rtmp_connect(ngx_http_request_t*r, ngx_rtmp_session_t*s){
	ngx_http_flv_live_ctx_t* ctx;
	ngx_uint_t					n;
//	u_char							tc_url[NGX_RTMP_MAX_URL];

	ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_app_conf_t  **cacfp;
	
	ngx_str_t	s_port = ngx_string("port");
	ngx_str_t	s_app = ngx_string("app");
	ngx_str_t	s_stream = ngx_string("stream");
	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
	
	if(ngx_http_arg(r, s_port.data, s_port.len, &ctx->port_from)!= NGX_OK){
		ctx->port_from.data= (u_char*)"1935";
		ctx->port_from.len= ngx_strlen("1935");
	}
	if(ngx_http_arg(r, s_app.data, s_app.len, &ctx->app_name)!= NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "flv live: app arg not found in url");
		return NGX_ERROR;
	}
	if(ngx_http_arg(r, s_stream.data, s_stream.len, &ctx->st_name)!= NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "flv live: app arg not found in url");
		return NGX_ERROR;
	}
	cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
	/* fill session parameters */
    s->connected = 1;

	s->app.len = ctx->app_name.len;
	s->app.data = ngx_pcalloc(s->connection->pool, s->app.len );
	ngx_memcpy(s->app.data, ctx->app_name.data, s->app.len);
/*	s->args.len = r->args.len;
	s->args.data = ngx_pcalloc(s->connection, s->args.len );
	ngx_memcpy(s->args.data, r->args.data, s->args.len);

	s->flashver = ngx_string("httplive 0.1");
	ngx_sprintf(tc_url, "http://%V/%V", r->headers_in.host->value, s->app);
	s->tc_url.len = ngx_strlen(tc_url);
	s->tc_url.data = ngx_pcalloc(s->connection, s->tc_url.len );
	ngx_memcpy(s->tc_url.data, r->tc_url.data, s->tc_url.len);
*/	
	/* find application & set app_conf */
	cacfp = cscf->applications.elts;
	for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
		if ((*cacfp)->name.len == s->app.len &&
			ngx_strncmp((*cacfp)->name.data, s->app.data, s->app.len) == 0){
			/* found app! */
			s->app_conf = (*cacfp)->app_conf;
			break;
		}
	}

	if (s->app_conf == NULL) {
		ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
					  "connect: application not found: '%V'", &s->app);
		return NGX_ERROR;
	}	
	return NGX_OK;
}

static ngx_rtmp_session_t*
ngx_http_flv_live_init_rtmp_session(ngx_http_request_t*r, ngx_rtmp_addr_conf_t *addr_conf){
	ngx_connection_t *c;
    ngx_rtmp_session_t             *s;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_error_log_ctx_t       *ctx;


	c = r->connection;
	s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t) +
	        sizeof(ngx_chain_t *) * ((ngx_rtmp_core_srv_conf_t *)
	            addr_conf->ctx-> srv_conf[ngx_rtmp_core_module
	                .ctx_index])->out_queue);
	if (s == NULL) {
	    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	    return NULL;
	}	
	s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;
    s->addr_text = &addr_conf->addr_text;
 
    s->connection = c;
	s->data = r;
	
    ctx = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_error_log_ctx_t));
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_rtmp_log_error;
    c->log->data = ctx;
    c->log->action = NULL;

    c->log_error = NGX_ERROR_INFO;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
       ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_stream_t)
            * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

#if (nginx_version >= 1007005)
    ngx_queue_init(&s->posted_dry_events);
#endif

    s->epoch = ngx_current_msec;
    s->timeout = cscf->timeout;
    s->buflen = cscf->buflen;
    ngx_rtmp_set_chunk_size(s, NGX_RTMP_DEFAULT_CHUNK_SIZE);


    if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }
    return s;
	
}
static ngx_rtmp_session_t*
ngx_http_flv_live_convert_connection_to_session(ngx_http_request_t *r){
	ngx_rtmp_session_t *s;
	ngx_rtmp_addr_conf_t *addr_conf;
	ngx_listening_t *ls;
	ngx_uint_t n,  is_find, net_port,i;
	ngx_rtmp_port_t 	  *port;
	struct sockaddr       *sa;
    struct sockaddr_in    *sin;
	ngx_rtmp_in_addr_t    *addr;
	ngx_str_t	s_port = ngx_string("port");
	ngx_str_t   hfls_port;

#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_rtmp_in6_addr_t   *addr6;
#endif

	is_find = 0;
	if(ngx_http_arg(r, s_port.data, s_port.len, &hfls_port)!= NGX_OK){
		hfls_port.data= (u_char*)"1935";
		hfls_port.len= ngx_strlen("1935");
	}

	net_port = htons(ngx_atoi(hfls_port.data, hfls_port.len));
	ls = ngx_cycle->listening.elts;
	for(n=0; n<ngx_cycle->listening.nelts; ++n,++ls){
		if(ls->handler == ngx_rtmp_init_connection){//找到对应rtmp的addr_conf
			sa = ls->sockaddr;
			switch(sa->sa_family){
#if (NGX_HAVE_INET6)
				case AF_INET6:
					sin6 = (struct sockaddr_in6 *)sa;
					if(sin6->sin_port == net_port){
						is_find = 1;
						goto FOUND;
					}
					break;
#endif
				default://AF_INET
					sin = (struct sockaddr_in *)sa;
					if(sin->sin_port == net_port){
						is_find = 1;
						goto FOUND;
					}
					break;			
				}				
		}	
	}	
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "flv live: listen port not found");
	return NULL;
FOUND:
	port = ls->servers;	
	if (port->naddrs > 1) {
		switch(sa->sa_family){
#if (NGX_HAVE_INET6)
		case AF_INET6:
			addr6 = port->addrs;
			for(i=0;;i<port->naddrs -1;i++){
				if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                	break;
           		}
			}
			addr_conf = &addr6[i].conf;
			break;
#endif
		default://AF_INET
			addr = port->addrs;
			for(i=0; i<port->naddrs -1; i++){
				if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
			}
			addr_conf = &addr[i].conf;
			break;			
		}				
	}else{
		switch(sa->sa_family){
#if (NGX_HAVE_INET6)
		case AF_INET6:
			addr6 = port->addrs;			
			addr_conf = &addr6[0].conf;
			break;
#endif
		default://AF_INET
			addr = port->addrs;	
			addr_conf = &addr[0].conf;
			break;			
		}
	}	
	s = ngx_http_flv_live_init_rtmp_session(r,addr_conf);
	if(s == NULL){
		return NULL;
	}
	if(ngx_http_flv_live_init_rtmp_connect(r, s) != NGX_OK){
		return NULL;
	}
	s->connection->write->handler = ngx_http_flv_live_send;
	s->connection->read->handler = ngx_http_flv_live_read;
	return s;
}
static void
ngx_http_flv_live_close_session(void*data){
	ngx_rtmp_session_t                 *s;
    ngx_connection_t                   *c;
    ngx_rtmp_core_srv_conf_t           *cscf;

	s = data;
    c = s->connection;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "close httpflv session");

    ngx_rtmp_fire_event(s, NGX_RTMP_DISCONNECT, NULL, NULL);

    if (s->ping_evt.timer_set) {
        ngx_del_timer(&s->ping_evt);
    }

    if (s->in_old_pool) {
        ngx_destroy_pool(s->in_old_pool);
    }

    if (s->in_pool) {
        ngx_destroy_pool(s->in_pool);
    }
    while (s->out_pos != s->out_last) {
        ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }	
}
//rtmp 加入stream，等待分发
static ngx_int_t 
ngx_http_flv_live_jion_rtmp_stream(ngx_rtmp_session_t*s){
	ngx_http_flv_live_ctx_t* ctx;
	ngx_rtmp_live_ctx_t* rtmp_ctx;
	ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_stream_t    **stream;
    size_t                      len;
	ngx_http_request_t			*r;
	
	r = s->data;

	lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
	if(ctx == NULL){
		return NGX_ERROR;
	}

	rtmp_ctx = ngx_http_get_module_ctx(s, ngx_rtmp_live_module);
	if(rtmp_ctx == NULL){		
		rtmp_ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_live_ctx_t));
		ngx_rtmp_set_ctx(s, rtmp_ctx, ngx_rtmp_live_module);
	}
	ngx_memzero(rtmp_ctx, sizeof(*rtmp_ctx));

    rtmp_ctx->session = s;

	rtmp_ctx->send_message_pt = ngx_http_flv_live_send_message;
	rtmp_ctx->prepare_message_pt = ngx_http_flv_live_prepare_message;
	rtmp_ctx->send_meta_data_pt = ngx_http_flv_live_send_meta_and_header;
	rtmp_ctx->live_type = NGX_LIVE_TYPE_HTTP_FLV;

	//get stream by stream name
	len = ctx->st_name.len;
	stream = &lacf->streams[ngx_hash_key(ctx->st_name.data, len) % lacf->nbuckets];	
	for (; *stream; stream = &(*stream)->next) {
	   if (ngx_memcmp(ctx->st_name.data, (*stream)->name, len) == 0) {
		  break;
	   }
	}
	
	 if (*stream == NULL || !((*stream)->publishing || lacf->idle_streams)) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
			"ngx_http_flv_live_jion_rtmp_stream not find stream %V", &ctx->st_name);
		return NGX_ERROR;
	 }

	rtmp_ctx->stream = *stream;
    rtmp_ctx->publishing = 0;
    rtmp_ctx->next = (*stream)->ctx;

    (*stream)->ctx = rtmp_ctx;

    if (lacf->buflen) {
        s->out_buffer = 1;
    }

    rtmp_ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    rtmp_ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

	return NGX_OK;
}


static ngx_int_t 
ngx_http_flv_live_handler(ngx_http_request_t *r){
	ngx_http_flv_live_loc_conf_t *hflf;
	ngx_http_flv_live_ctx_t* ctx;
	ngx_http_cleanup_t *hcln;
	ngx_rtmp_session_t *s;
	
	
	hflf = ngx_http_get_module_loc_conf(r, ngx_http_flv_live_module);
	if(!hflf->http_flv_live){
		return NGX_DECLINED;
	}
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_flv_live_handler");
	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
	if(ctx == NULL){
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_flv_live_ctx_t));
		ngx_http_set_ctx(r, ctx, ngx_http_flv_live_module);
	}
	ctx->s = ngx_http_flv_live_convert_connection_to_session(r);
	if(ctx->s == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}	

	
	r->allow_ranges = 1;
    r->read_event_handler = ngx_http_test_reading;
	hcln = ngx_http_cleanup_add(r, 0);
	if(hcln == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	s = ctx->s;
	hcln->handler = ngx_http_flv_live_close_session;
	hcln->data = s;
	
	if(ngx_http_flv_live_jion_rtmp_stream(s) != NGX_OK){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	r->count++;
	return NGX_OK;
}

static ngx_int_t
ngx_http_flv_live_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;
	cmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if(h == NULL){
		return NGX_ERROR;
	}
	*h = ngx_http_flv_live_handler;
	
	return NGX_OK;
}

#define FLV_TAG_LEN 11

static ngx_chain_t* ngx_http_flv_live_prepare_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_header_t *lh, ngx_chain_t *in)
{
	
	ngx_rtmp_core_srv_conf_t	   *cscf;
	ngx_chain_t *last_chunk, *l, *tag_chain;//用于最后填充tag_size
	
	u_char *p, *pp;
	uint32_t 	tag_size, data_size;
	
	tag_size = data_size = 0;
	cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
	tag_chain = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
	
	last_chunk = tag_chain;
	for(l = tag_chain;l; l = l->next){
		last_chunk = l;
		data_size += (l->buf->last - l->buf->pos);
	}
	//add flv header
	tag_chain->buf->pos -= FLV_TAG_LEN;
	p = tag_chain->buf->pos;
	*p++ = h->type;
	pp = (u_char*)&data_size;
	*p++ = pp[2];
	*p++ = pp[1];
	*p++ = pp[0];
	pp = (u_char*)&h->timestamp;
	*p++ = pp[3];
	*p++ = pp[2];
	*p++ = pp[1];
	*p++ = pp[0];
	*p++ = 0;
	*p++ = 0;
	*p++ = 0;
	
	if(last_chunk->buf->end - last_chunk->buf->last<4){	
		last_chunk->next = ngx_rtmp_alloc_shared_buf(cscf);
		last_chunk = last_chunk->next;
	}
	tag_size = FLV_TAG_LEN+ data_size;
	pp = (u_char*)&tag_size;
	*last_chunk->buf->last++ = pp[3];
	*last_chunk->buf->last++ = pp[2];
	*last_chunk->buf->last++ = pp[1];
	*last_chunk->buf->last++ = pp[0];
	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
		"videotype:%d   ,  timestamp:%d ",h->type,h->timestamp);
    return tag_chain;
}

static void
ngx_http_flv_live_read(ngx_event_t *rev)
{
	
	ngx_connection_t 		*c;
	ngx_rtmp_session_t 		*s;
	ngx_http_request_t		*r;
	ngx_http_flv_live_ctx_t *ctx;	
	u_char				buf[1024];	
	ssize_t  n;
	
	c = rev->data;
	r = c->data;
	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
	s = ctx->s;
	
	if (c->destroyed) {
		return;
	}
	
	if(c->timedout){

	}
	if (rev->timer_set) {
       // ngx_del_timer(rev);
    }
	while(1){
		n = c->recv(c , buf, 1024 );
		if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_finalize_session(s);
            return;
        }
		
		if(n == NGX_AGAIN){
			//add timer
			return;
		}
	}

}
static void
ngx_http_flv_live_send(ngx_event_t *wev)
{
	ngx_connection_t		   *c;
	ngx_rtmp_session_t		 *s;
	ngx_int_t 				  n;
	ngx_rtmp_core_srv_conf_t	 *cscf;
	ngx_http_flv_live_ctx_t *ctx;
	ngx_http_request_t *r;	

	c = wev->data;
	r = c->data; 
	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
	s = ctx->s;

	//ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
	//			"ngx_rtmp_send start!");

	if (c->destroyed) {
		return;
	}

	if (wev->timedout) {
		ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
			  "client timed out");
		c->timedout = 1;
		ngx_rtmp_finalize_session(s);
		return;
	}

	if (wev->timer_set) {
		ngx_del_timer(wev);
	}

	if (s->out_chain == NULL && s->out_pos != s->out_last) {
		s->out_chain = s->out[s->out_pos];
		s->out_bpos = s->out_chain->buf->pos;
	}

	while (s->out_chain) {
	  n = c->send(c, s->out_bpos, s->out_chain->buf->last - s->out_bpos);

	  if (n == NGX_AGAIN || n == 0) {
		  ngx_add_timer(c->write, s->timeout);
		  if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
			  ngx_rtmp_finalize_session(s);
		  }
		  return;
	  }

	  if (n < 0) {
		  ngx_rtmp_finalize_session(s);
		  return;
	  }

	  s->out_bytes += n;
	  s->ping_reset = 1;
	  ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_out, n);


	  s->out_bpos += n;
	  if (s->out_bpos == s->out_chain->buf->last) {
		  s->out_chain = s->out_chain->next;
		  if (s->out_chain == NULL) {
			  cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
			  ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos]);
			  ++s->out_pos;
			  s->out_pos %= s->out_queue;
			  if (s->out_pos == s->out_last) {
				  break;
			  }
			  s->out_chain = s->out[s->out_pos];
		  }
		  s->out_bpos = s->out_chain->buf->pos;
	  }
	}

	if (wev->active) {
		ngx_del_event(wev, NGX_WRITE_EVENT, 0);
	}

	ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &s->posted_dry_events);

}

static ngx_int_t ngx_http_flv_live_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        unsigned int priority)
{
	ngx_uint_t                      nmsg;
	
#ifdef WRITE_FLV_FILE
	ngx_chain_t *pkt;
	size_t            len;
    ssize_t           n;
#endif
    nmsg = (s->out_last - s->out_pos) % s->out_queue + 1;

    if (priority > 3) {
        priority = 3;
    }


#ifdef WRITE_FLV_FILE
		if(g_fd == -1 && g_count ==0){
			g_fd = ngx_open_file("test.flv", NGX_FILE_RDWR, NGX_FILE_TRUNCATE, 0);
			if (g_fd == NGX_INVALID_FILE) {
				  ngx_log_error(NGX_LOG_ERR, s->connection->log,ngx_errno, "ngx_open_file failed");
			}
		}
		if(g_fd != -1){
			for(pkt = out; pkt;pkt = pkt->next){
				len = pkt->buf->last - pkt->buf->pos;
				n = ngx_write_fd(g_fd, pkt->buf->pos, len);
				if (n == -1) {
					ngx_log_error(NGX_LOG_ERR, s->connection->log,ngx_errno, "ngx_write_fd failed");
				}
				if ((size_t) n != len) {
					ngx_log_error(NGX_LOG_ERR, s->connection->log,ngx_errno, 
						" has written only %z of %uz ", n, len);				
				}
			}
		}
		
		if(g_count++ > 500){
			if (g_fd != -1 && ngx_close_file(g_fd) == NGX_FILE_ERROR) {
           		 ngx_log_error(NGX_LOG_ALERT, s->connection->log, ngx_errno,
                          "ngx_close_file failed");
				 g_fd = -1;
        	}
		}
		
#endif



	

    /* drop packet?
     * Note we always leave 1 slot free */
    if (nmsg + priority * s->out_queue / 4 >= s->out_queue) {
        ngx_log_debug2(NGX_LOG_ERR, s->connection->log, 0,
                "http flv drop message bufs=%ui, priority=%ui",
                nmsg, priority);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
    s->out_last %= s->out_queue;

    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "http flv send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);

    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {
        ngx_http_flv_live_send(s->connection->write);      
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_flv_live_send_meta_and_header(ngx_rtmp_session_t *s, ngx_chain_t *meta_pkt,
        unsigned int priority)
{
	ngx_rtmp_core_srv_conf_t	   *cscf;
	u_char				*p,*pp;
	uint8_t             fmt;
	ngx_int_t			meta_header_size;			
	ngx_chain_t			*meta_data, *meta, *head,**tmp, *pkt;
	ngx_rtmp_header_t      h;
	ngx_http_request_t *r;
	ngx_http_flv_live_ctx_t *ctx;
	if(ngx_http_flv_live_send_flv_header(s)!= NGX_OK){
		ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_flv_live_send_flv_header error");
		return NGX_ERROR;
	}
	meta_data=meta=pkt=head=NULL;
	r=s->data;
	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
	//covert rtmp meta to flv metadata
	meta_header_size = 0;
	p = meta_pkt->buf->pos;
	fmt  = (*p >> 6) & 0x03;
	h.csid= *p++ & 0x3f;
	if(h.csid == 0){
		h.csid = 64;
		h.csid += *(uint8_t*)p++;
	}else if(h.csid == 1){
		h.csid = 64;
        h.csid += *(uint8_t*)p++;
        h.csid += (uint32_t)256 * (*(uint8_t*)p++);
	}
	if (fmt <= 2 ) {
		pp = (u_char*)&h.timestamp;
        pp[2] = *p++;
        pp[1] = *p++;
        pp[0] = *p++;
        pp[3] = 0;
		if (fmt <= 1) {
			pp = (u_char*)&h.mlen;
			pp[2] = *p++;
			pp[1] = *p++;
			pp[0] = *p++;
			pp[3] = 0;
			h.type = *(uint8_t*)p++;
			if (fmt == 0) {	
				/* stream:
				 *  little-endian 4b -> little-endian 4b */
				pp = (u_char*)&h.msid;
				pp[0] = *p++;
				pp[1] = *p++;
				pp[2] = *p++;
				pp[3] = *p++;
			}
		}
	}
	 /* extended header */
 	if(h.timestamp == 0x00ffffff){
        pp = (u_char*)&h.timestamp;
        pp[3] = *p++;
        pp[2] = *p++;
        pp[1] = *p++;
        pp[0] = *p++;
    }
	
	meta_header_size = p - meta_pkt->buf->pos;
	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
		"ngx_http_flv_live_send_meta_and_header meta_header_size:%d", meta_header_size);
	/* headers to successive fragments */
	tmp = &head;
    for(meta_data = meta_pkt; meta_data; meta_data = meta_data->next) {		
		meta = ngx_chain_get_free_buf(s->connection->pool, &ctx->free);
		ngx_memcpy(meta->buf, meta_data->buf, sizeof(ngx_buf_t));
		meta->buf->pos += meta_header_size;
		*tmp = meta;
		tmp = &((*tmp)->next);
	}	
	cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
	pkt = ngx_http_flv_live_prepare_message(s,  &h, NULL, head);
	
	if(ngx_http_flv_live_send_message(s, pkt, 0)!=NGX_OK){
		return NGX_ERROR;
	}
	ngx_rtmp_free_shared_chain(cscf, pkt); 
	return NGX_OK;
	
}
static ngx_int_t ngx_http_flv_live_send_flv_header(ngx_rtmp_session_t *s){
	ngx_rtmp_core_srv_conf_t	   *cscf;
	ngx_rtmp_codec_ctx_t		   *codec_ctx;
	ngx_rtmp_live_ctx_t				*rtmp_ctx,*it_ctx;
	ngx_http_request_t *r; 
	ngx_http_flv_live_ctx_t *ctx;
	ngx_chain_t r_pkt,h_pkt, *ppkt;
	ngx_buf_t	r_buf, h_buf;
	
	const ngx_str_t http_response_header =ngx_string(
		"HTTP/1.1 200 OK"
	   CRLF	   
	   "Server: NginxHttpFlv"
	   CRLF
	   "Content-Type: video/x-flv"
	   CRLF
	   "Connection: keep-alive"
	   CRLF
	   "Pragma: no-cache"
	   CRLF
	   "Cache-Control: no-cache"
	   CRLF
	   "Expires: -1"
	   CRLF
	   CRLF);
	u_char flv_header[] = "FLV\x1\0\0\0\0\x9\0\0\0\0"; //有待设定

	cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

	r = s->data; 
	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
	
	
	rtmp_ctx = ngx_http_get_module_ctx(s, ngx_rtmp_live_module);
	if(rtmp_ctx == NULL){
			return NGX_ERROR;
	}
	codec_ctx = NULL;
	for(it_ctx = rtmp_ctx ;it_ctx;it_ctx = it_ctx->next){
		if(it_ctx->publishing){
			codec_ctx = ngx_rtmp_get_module_ctx(it_ctx->session, ngx_rtmp_codec_module);
		}
	}
	if(codec_ctx == NULL){
		ngx_log_error(NGX_LOG_ERR, s->connection->log,0, "codec_ctx == NULL");
		return NGX_ERROR;
	}

	if(codec_ctx->aac_header){
		flv_header[4] |= 0x04;
	}
	if(codec_ctx->avc_header){
		flv_header[4] |= 0x01;
	}

	ngx_memzero(&r_buf, sizeof(r_buf));
	ngx_memzero(&h_buf, sizeof(h_buf));
	r_pkt.buf = &r_buf;
	r_pkt.buf->start = r_pkt.buf->pos = http_response_header.data;	
	r_pkt.buf->end = r_pkt.buf->last = http_response_header.data + http_response_header.len;
	
	h_pkt.buf = &h_buf;		
	h_pkt.buf->start = h_pkt.buf->pos = flv_header;	
	h_pkt.buf->end  = h_pkt.buf->last= flv_header + 13;
	
	r_pkt.next = &h_pkt;	
	h_pkt.next = NULL;	
	ppkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &r_pkt);
	
	if(ngx_http_flv_live_send_message(s, ppkt, 0)!=NGX_OK){
		return NGX_ERROR;
	}
	ngx_rtmp_free_shared_chain(cscf, ppkt);	

	return NGX_OK;
}



