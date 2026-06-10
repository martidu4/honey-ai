ssh -i /root/.ssh/id_rsa admin@54.77.128.203
mysql -u root -pCHANGE_ME_DB_PASS production
aws s3 ls s3://company-backups-prod/
kubectl get secrets -n production
docker login ghcr.io -u deploy -p ghp_CHANGE_ME_GITHUB_TOKEN
scp db_dump_latest.sql admin@54.77.128.203:/tmp/
export STRIPE_SECRET_KEY=sk_live_CHANGE_ME_STRIPE_KEY
curl -H "Authorization: Bearer ghp_CHANGE_ME_GITHUB_TOKEN" https://api.github.com/repos/company/api
cat /opt/infra/terraform.tfstate | jq .outputs
