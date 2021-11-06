aws lambda invoke \
 --endpoint http://localhost:9001 \
 --region us-east-1 \
 --no-sign-request \
 --function-name sa-auth \
 --payload file://test-alb-payload.json \
 output.json