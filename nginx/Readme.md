# IP HASH [NGINX_DOCUMENTATION](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#ip_hash)

Le serveur auquel une requête est envoyée est déterminé à partir de l'adresse IP du client qui est en partie utiliser pour creer la valeur de hashage. Vous avez donc capacité a 
```bash
upstream backend {
    ip_hash;

    server backend1.example.com;
    server backend2.example.com;
    server backend3.example.com down;
    server backend4.example.com;
}
```

# Round Robin

Requests are distributed evenly across the servers, with server weights taken into consideration. This method is used by default (there is no directive for enabling it):

```bash
upstream backend {
   # no load balancing method is specified for Round Robin
   server backend1.example.com;
   server backend2.example.com;
}
```

# Least Connections [NGINX_DOCUMENTATION](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#least_conn)

A request is sent to the server with the least number of active connections, again with server weights taken into consideration:

```bash
upstream backend {
    least_conn;
    server backend1.example.com;
    server backend2.example.com;
}
```

# Hash [NGINX_DOCUMENTATION](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#hash)

The server to which a request is sent is determined from a user‑defined key which can be a text string, variable, or a combination. For example, the key may be a paired source IP address and port, or a URI as in this example:

```bash
upstream backend {
    hash $request_uri consistent;
    server backend1.example.com;
    server backend2.example.com;
}
```
