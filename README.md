# ngx_rtmp_http_flv_module
把rtmp流简单的转换成httpflv格式的直播流，可以使用flv.js播放


#配置

server{
	...
		location /live{
                http_flv on; #live 请求httpflv流
        }
	}
rtmp 推流：rtmp://xxxx:1935/live/vae
	app :rtmp application
	stream :rtmp stream name
请求的http参数：http://xxxx:8080/live?app=live&stream=vae
