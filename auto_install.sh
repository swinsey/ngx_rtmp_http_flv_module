#!/bin/sh

echo "install start~~"
rm -rf nginx-1.9.3
rm -rf nginx-rtmp-module-master

tar -zxvf nginx-1.9.3.tar.gz
unzip  nginx-rtmp-module-master.zip

\cp -f  ngx_http_flv_module/* nginx-rtmp-module-master/
cd nginx-1.9.3/
./configure --prefix=/usr/local/nginx  --add-module=../nginx-rtmp-module-master
make -j8 && make install

cd ../
\cp nginx.conf /usr/local/nginx/conf/
cp -rf web_static /usr/local/nginx/html/
echo "install done~~"
