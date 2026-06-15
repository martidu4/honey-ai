const MAZE_FILES = [
  // ... existing files ...
  {
    name: 'docker-compose.yml',
    content: `version: '3'
services:
  db:
    image: postgres
    environment:
      - POSTGRES_USER=myuser
      - POSTGRES_PASSWORD=mypassword
  web:
    build: .
    ports:
      - '80:80'
    depends_on:
      - db
`,
    isRealBinary: false
  },
  {
    name: 'terraform.tfvars',
    content: `aws_access_key_id = 'myaccesskey'
aws_secret_access_key = 'mysecretkey'
region = 'us-east-1'
instance_type = 't2.micro'
`,
    isRealBinary: false
  },
  {
    name: 'ansible-vault.yml',
    content: `ansible_vault_password_file: /path/to/vault/password
`,
    isRealBinary: false
  },
  {
    name: '.htpasswd',
    content: `user1:$apr1$...$...
user2:$apr1$...$...
`,
    isRealBinary: false
  },
  {
    name: 'authorized_keys',
    content: `ssh-rsa ... user1
ssh-rsa ... user2
`,
    isRealBinary: false
  },
  {
    name: 'ssl-cert.pem',
    content: `-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
`,
    isRealBinary: false
  },
  {
    name: 'api-keys.json',
    content: `{
  "stripe": "my_stripe_key",
  "twilio": "my_twilio_key",
  "sendgrid": "my_sendgrid_key"
}
`,
    isRealBinary: false
  },
  {
    name: 'employee-list.xlsx',
    isRealBinary: true
  },
  {
    name: 'financial-report-2024.pdf',
    isRealBinary: true
  },
  {
    name: 'server-inventory.csv',
    content: `server,ip,credentials
server1,192.168.1.1,myuser:mypassword
server2,192.168.1.2,myuser:mypassword
`,
    isRealBinary: false
  }
];