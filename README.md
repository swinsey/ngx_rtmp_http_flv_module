# ngx_rtmp_http_flv_module
把rtmp流简单的转换成httpflv格式的直播流，可以使用flv.js播放

基于nginx-1.9.3 rtmp-module

# 使用
* 进入目录 ./auto_install.sh 安装(出现ssl错误则需要安装openssl的相关库)

* /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf 运行nginx

* 在支持flv.js的浏览器中输入： http\://192.168.8.xx:8080/httpflvjs.html 
* 不支持的浏览器输入：http\://192.168.8.xx:8080/httpflv.html 

# 配置
* nginx
			
		server{ 
		...		
		location /live{		
            	    http_flv on; #live 请求httpflv流 		    
       		 } 		 
		} 
	
* http url

		rtmp 推流：rtmp://xxxx:1935/live/vae		
		`app` :rtmp application 
		`stream` :rtmp stream name 
		
		请求的http参数：http://xxxx:8080/live?app=live&stream=vae 
