This patch is for Nginx to get real client ip by 'toa_remote_addr' 
when you are using NAT64 mode(VIP is IPv6 while RS is IPv4).
You can use this patch only when toa module is installed.

Here is an exampe to configure http block in nginx.conf:

```
http {
    include       mime.types;
    default_type  application/octet-stream;

    log_format  main  '$toa_remote_addr $toa_remote_port $remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /data/nginx/logs/access.log  main;

    keepalive_timeout  65; 

    server {
        listen       80; 
        server_name  localhost;

        access_log  /data/nginx/logs/access.log  main;

        location / {
            proxy_set_header X-Forwarded-For $toa_remote_addr; 
            proxy_pass http://192.168.1.1;
        }   
    }   
}
```
