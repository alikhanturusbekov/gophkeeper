# Менеджер паролей GophKeeper

GophKeeper представляет собой клиент-серверную систему, позволяющую пользователю 
надёжно и безопасно хранить логины, пароли, бинарные данные и прочую приватную информацию.

## Makefile команды

```
make postgres        start PostgreSQL in Docker
make postgres-stop   stop the container
make postgres-reset  stop + delete data volume
make run-server      build & run server locally
make build           build server + client binaries → bin/
make build-server    build server only
make build-client    build client only
make test            run all unit tests
make cover           generate HTML coverage report
make lint            go vet
make clean           remove bin/ and coverage files
```
