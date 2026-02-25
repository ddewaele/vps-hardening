# Conn3ctivity checks


## Quick HTTP check (works almost everywhere)
```
docker run --rm curlimages/curl:8.6.0 -fsSL https://example.com >/dev/null && echo OK || echo FAIL
```

## DNS check (often the real culprit)
```
docker run --rm busybox:1.36 nslookup google.com
```

## Ping check (often blocked, so don’t trust failures too much)
```
docker run --rm busybox:1.36 ping -c 3 1.1.1.1
```

## Interactive “debug shell” in a container
```
docker run --rm -it --pull=always nicolaka/netshoot sh
# then inside:
curl -I https://example.com
dig google.com
ip route
```

## Launching a python webserver

```
python3 -m http.server 8000
```


## Docker compose

### nginx.conf

```
server {
  listen 80;

  # Direct hit to frontend
  location = / {
    return 200 "hello from frontend\n";
  }

  # Proxy to backend (internal-only)
  location /backend/ {
    proxy_pass http://backend:8080/;
  }
}
```

### docker compose.yml


```
services:
  backend:
    image: hashicorp/http-echo:1.0
    command: ["-listen=:8080", "-text=hello from backend"]
    expose:
      - "8080"
    networks:
      - connectivity-test

  frontend:
    image: python:3.12-alpine
    ports:
      - "8000:8000"   # exposed to the outside
    networks:
      - connectivity-test
    command: >
      sh -lc "
        echo 'hello from frontend' > /srv/index.html &&
        python -m http.server 8000 --directory /srv --bind 0.0.0.0
      "

  frontend-nginx:
    image: nginx:alpine
    ports:
      - "80:80"   # binds on 0.0.0.0 by default
    depends_on:
      - backend
    networks:
      - connectivity-test
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro

networks:
  connectivity-test:
    driver: bridge
```

### checks

```
curl http://localhost/
curl http://localhost/backend/

docker compose exec frontend sh
docker compose exec backend sh
```

should work in the frontend container:
```
wget -qO- http://backend:8080/
wget -qO- http://localhost/backend/
```

# should not work
```
curl -v http://YOUR_SERVER_IP:8080/
```


## ufw tests

```
sudo ufw allow 8111/tcp comment 'HTTP test'
sudo ufw delete allow 8111/tcp
```

## iptables tests

```
ubuntu@vps-d405ed6c:~$ sudo iptables -L -n | grep 3080
ACCEPT     6    --  0.0.0.0/0            172.18.0.6           tcp dpt:3080
```
vs
```
ubuntu@b2-7-de1:~$ sudo iptables -L -n | grep 3080
ACCEPT     tcp  --  0.0.0.0/0            172.18.0.7           tcp dpt:3080
```


```
ubuntu@b2-7-de1:~$ sudo iptables -t nat -S | grep 3080
-A DOCKER ! -i br-7526c5b551a2 -p tcp -m tcp --dport 3080 -j DNAT --to-destination 172.18.0.7:3080
ubuntu@b2-7-de1:~$ sudo ss -ltnp | grep ':3080'
LISTEN 0      4096         0.0.0.0:3080      0.0.0.0:*    users:(("docker-proxy",pid=59446,fd=8))
LISTEN 0      4096            [::]:3080         [::]:*    users:(("docker-proxy",pid=59452,fd=8))

ubuntu@vps-d405ed6c:~$ sudo iptables -t nat -S | grep 3080
-A DOCKER -d 127.0.0.1/32 ! -i br-66f1bc0b21ee -p tcp -m tcp --dport 3080 -j DNAT --to-destination 172.18.0.6:3080
ubuntu@vps-d405ed6c:~$ sudo ss -ltnp | grep ':3080'
LISTEN 0      4096       127.0.0.1:3080       0.0.0.0:*    users:(("docker-proxy",pid=4481,fd=7))
```