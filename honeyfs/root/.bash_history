ssh -i /root/.ssh/id_rsa admin@54.77.128.203
mysql -u root -pKx9$mP2vL8nQw4jR production
aws s3 ls s3://company-backups-prod/
kubectl get secrets -n production
docker login ghcr.io -u deploy -p ghp_R4nD0mT0k3nV4lu3F0rD3pl0ym3ntAcc3ss42
scp db_dump_latest.sql admin@54.77.128.203:/tmp/
export STRIPE_SECRET_KEY=sk_live_51N3xAmPl3K3y4Str1p3P4yM3nts
curl -H "Authorization: Bearer ghp_R4nD0mT0k3nV4lu3F0rD3pl0ym3ntAcc3ss42" https://api.github.com/repos/company/api
cat /opt/infra/terraform.tfstate | jq .outputs
