# Unifi CertBot
> Service for auto updating SSL Certs on the Unifi Dream Machine Pro

The Unifi Dream Machine Pro only ships with self-signed certs SSL/TLS certificates that will show a warning
in most browsers. Unifi CertBot leverages [Let's Encrypt](https://letsencrypt.org/) to issue publicly trusted
certificates for your UDMP and keep them up to date.