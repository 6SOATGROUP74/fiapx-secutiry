docker build -t 6soatgroup74/fiapx-security:prod .
docker push 6soatgroup74/fiapx-security:prod

aws eks update-kubeconfig --region us-east-1 --name shogun-cluster-eks