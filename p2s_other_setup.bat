@echo off
setlocal EnableExtensions
REM ============================================================
REM  P2S — Diğer PoC hedefleri (Windows Docker Desktop, native amd64)
REM  Kur: Ghostcat + h2c + Apache mod_http2 + MySQL 5.7/8.0 + PHP CGI/FPM
REM  Detay: P2S_OTHER_TARGETS.md
REM ============================================================
echo [P2S] Docker kontrol...
docker version >nul 2>&1 || (echo [!] Docker calismiyor. Docker Desktop'i ac ve tekrar dene. & exit /b 1)
echo [P2S] Image cekiliyor (linux/amd64)...

docker pull --platform linux/amd64 tomcat:9.0.30
docker pull --platform linux/amd64 nginx:1.22
docker pull --platform linux/amd64 httpd:2.4
docker pull --platform linux/amd64 mysql:5.7
docker pull --platform linux/amd64 mysql:8.0
docker pull --platform linux/amd64 nginx:1.20
docker pull --platform linux/amd64 php:7.4-fpm

REM ---- 1) Ghostcat (Tomcat 9.0.30) 18201/18202 ----
docker rm -f p2s-ghostcat 2>nul
docker run -d --name p2s-ghostcat --restart unless-stopped -p 18201:8080 -p 18202:8009 tomcat:9.0.30
docker exec p2s-ghostcat sh -c "grep -q 'port=\"8009\"' /usr/local/tomcat/conf/server.xml || sed -i '/<\/Server>/i\  <Connector port=\"8009\" protocol=\"AJP/1.3\" redirectPort=\"8443\" secretRequired=\"false\"/>' /usr/local/tomcat/conf/server.xml"
docker restart p2s-ghostcat

REM ---- 2) nginx h2c (Rapid Reset) 18203 ----
docker rm -f p2s-h2c 2>nul
docker run -d --name p2s-h2c --restart unless-stopped -p 18203:80 nginx:1.22
echo "server{listen 80 http2;server_name _;root /usr/share/nginx/html;index index.html;}" > "%TEMP%\p2s_h2c.conf"
docker cp "%TEMP%\p2s_h2c.conf" p2s-h2c:/etc/nginx/conf.d/default.conf
docker exec p2s-h2c nginx -s reload

REM ---- 3) Apache mod_http2 18205 ----
docker rm -f p2s-apacheh2 2>nul
docker run -d --name p2s-apacheh2 --restart unless-stopped -p 18205:80 httpd:2.4
docker exec p2s-apacheh2 sh -c "a2enmod http2 proxy 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; (echo 'Protocols h2 http/1.1' > /etc/apache2/conf-available/h2c.conf && a2enconf h2c) 2>/dev/null || true"
docker restart p2s-apacheh2

REM ---- 4) MySQL 5.7  18210 ----
docker rm -f p2s-mysql57 2>nul
docker run -d --name p2s-mysql57 --restart unless-stopped -e MYSQL_ROOT_PASSWORD=p2s_test_123 -e MYSQL_DATABASE=p2s -p 18210:3306 mysql:5.7

REM ---- 5) MySQL 8.0  18211 ----
docker rm -f p2s-mysql80 2>nul
docker run -d --name p2s-mysql80 --restart unless-stopped -e MYSQL_ROOT_PASSWORD=p2s_test_123 -e MYSQL_DATABASE=p2s -p 18211:3306 mysql:8.0

REM ---- 6) PHP CGI/FPM  18215 ----
docker network create p2s-phpnet 2>nul
docker rm -f p2s-phpfpm 2>nul
docker run -d --name p2s-phpfpm --restart unless-stopped --network p2s-phpnet --network-alias php php:7.4-fpm
docker rm -f p2s-phpcgi 2>nul
docker run -d --name p2s-phpcgi --restart unless-stopped --network p2s-phpnet -p 18215:80 nginx:1.20
(
echo server {
echo     listen 80;
echo     server_name _;
echo     root /usr/share/nginx/html;
echo     index index.php;
echo     location ~ \.php(/|$) {
echo         fastcgi_split_path_info ^(.+\.php)(/.*)$;
echo         fastcgi_pass php:9000;
echo         fastcgi_index index.php;
echo         include fastcgi_params;
echo         fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
echo         fastcgi_param PATH_INFO $fastcgi_path_info;
echo     }
echo     location /cgi-bin/ {
echo         fastcgi_pass php:9000;
echo         include fastcgi_params;
echo         fastcgi_param SCRIPT_FILENAME /usr/local/bin/php-cgi;
echo     }
echo }
) > "%TEMP%\p2s_phpcgi.conf"
docker cp "%TEMP%\p2s_phpcgi.conf" p2s-phpcgi:/etc/nginx/conf.d/default.conf
echo '<?php echo "P2S-PHP-OK\n"; ?>' > "%TEMP%\p2s_index.php"
docker cp "%TEMP%\p2s_index.php" p2s-phpcgi:/usr/share/nginx/html/index.php
docker exec p2s-phpcgi nginx -t
docker exec p2s-phpcgi nginx -s reload

REM ---- Firewall (18201-18220 LAN acik) ----
netsh advfirewall firewall add rule name="p2s-other" dir=in action=allow protocol=TCP localport=18201-18220 >nul 2>&1

echo.
echo [P2S] Durum:
docker ps --filter "name=p2s" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
echo.
echo [P2S] Dogrula:
echo   curl http://127.0.0.1:18201/            (Tomcat 200)
echo   curl --http2-prior-knowledge http://127.0.0.1:18203/   (http_version=2)
echo   curl http://127.0.0.1:18215/index.php   (P2S-PHP-OK)
echo   Test-NetConnection 127.0.0.1 -Port 18210/18211/18202   (True)
endlocal
