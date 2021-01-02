# openssl 命令

- openssl genrsa -out rsa.key 2048
- openssl ecparam -genkey -name prime256v1 -out ecc.key
- openssl pkcs8 -topk8 -inform PEM -in rsa.key -outform PEM -nocrypt -out rsa_pkcs8.key # 将pkcs1 私钥转成java 使用的pkcs8格式
- openssl req -x509 -new -days 365 -key rsa.key -out cert.crt  # 生成证书

生成的ecc.key 包含 ```BEGIN EC PARAMETERS``` 在解析的时候需要去除掉
