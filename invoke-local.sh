aws lambda invoke \
 --endpoint http://localhost:9001 \
 --region us-east-1 \
 --no-sign-request \
 --function-name sa-auth \
 --payload '{"httpMethod":"GET","path":"/auth/login","queryStringParameters":{},"headers":{},"isBase64Encoded":false,"body":""}' \
 output.json